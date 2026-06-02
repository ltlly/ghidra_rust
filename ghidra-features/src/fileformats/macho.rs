//! Complete Mach-O and FAT (Universal) binary format parser.
//!
//! Supports:
//! - Universal (FAT) binaries with both endiannesses (FAT_MAGIC, FAT_CIGAM)
//! - 32-bit and 64-bit Mach-O files (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64)
//! - All standard load commands (segment, symtab, dyld, uuid, build_version, etc.)
//! - Export trie parsing
//! - DYLD opcode-based binding/rebase tables (lazy, weak, and normal bind)
//! - Chained fixups with pointer authentication
//! - Code signature blob parsing (CSMAGIC_REQUIREMENT, CSMAGIC_ENTITLEMENTS, CSMAGIC_BLOBWRAPPER)
//! - NList64 symbol table entries
//! - LC_DYLD_EXPORTS_TRIE and LC_DYLD_CHAINED_FIXUPS
//!
//! References:
//! - <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>
//! - <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/fat.h>
//! - <https://opensource.apple.com/source/dyld/dyld-852.2/>
//!
//! Basic usage:
//! ```ignore
//! use macho::{parse_macho, parse_fat};
//! let macho = parse_macho(&data)?;
//! println!("Header: {:?}", macho.header);
//! ```

use nom::bytes::complete::take;
use nom::multi::count;
use nom::number::complete::{be_i32, be_u32, le_i32, le_u32, le_u64};
use nom::IResult;
use std::collections::HashSet;
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Magic Numbers
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// 32-bit big-endian magic number.
pub const MH_MAGIC: u32 = 0xfeedface;
/// 32-bit little-endian magic number.
pub const MH_CIGAM: u32 = 0xcefaedfe;
/// 64-bit big-endian magic number.
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
/// 64-bit little-endian magic number. Use this for x86_64 and arm64 binaries.
pub const MH_CIGAM_64: u32 = 0xcffaedfe;
/// FAT/Universal binary magic (big-endian).
pub const FAT_MAGIC: u32 = 0xcafebabe;
/// FAT/Universal binary magic (little-endian).
pub const FAT_CIGAM: u32 = 0xbebafeca;

/// Returns true if the given u32 is any valid Mach-O magic value.
pub fn is_macho_magic(magic: u32) -> bool {
    matches!(magic, MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64)
}

/// Returns true if the magic indicates a 64-bit Mach-O binary.
pub fn is_macho_64(magic: u32) -> bool {
    matches!(magic, MH_MAGIC_64 | MH_CIGAM_64)
}

/// Returns true if the magic is a little-endian (CIGAM) variant.
pub fn is_macho_le(magic: u32) -> bool {
    matches!(magic, MH_CIGAM | MH_CIGAM_64)
}

/// Returns true if the given u32 is a FAT/universal binary magic.
pub fn is_fat_magic(magic: u32) -> bool {
    matches!(magic, FAT_MAGIC | FAT_CIGAM)
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// CPU Types
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Mask applied to cpu type to extract architecture bits.
pub const CPU_ARCH_MASK: i32 = 0xff00_0000u32 as i32;
/// 64-bit ABI flag. OR this into a cpu type to make it 64-bit.
pub const CPU_ARCH_ABI64: i32 = 0x0100_0000u32 as i32;
/// 64-bit hardware running 32-bit types (LP32). Used by ARM64_32.
pub const CPU_ARCH_ABI64_32: i32 = 0x0200_0000u32 as i32;

pub const CPU_TYPE_ANY: i32 = -1;
pub const CPU_TYPE_VAX: i32 = 1;
pub const CPU_TYPE_MC680X0: i32 = 6;
pub const CPU_TYPE_X86: i32 = 7;
pub const CPU_TYPE_I386: i32 = CPU_TYPE_X86;
pub const CPU_TYPE_MC98000: i32 = 10;
pub const CPU_TYPE_HPPA: i32 = 11;
pub const CPU_TYPE_ARM: i32 = 12;
pub const CPU_TYPE_MC88000: i32 = 13;
pub const CPU_TYPE_SPARC: i32 = 14;
pub const CPU_TYPE_I860: i32 = 15;
pub const CPU_TYPE_POWERPC: i32 = 18;
pub const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;
pub const CPU_TYPE_X86_64: i32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64_32: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;

/// Return a human-readable name for a CPU type constant.
pub fn cpu_type_name(cpu_type: i32) -> &'static str {
    match cpu_type {
        CPU_TYPE_ANY => "ANY",
        CPU_TYPE_VAX => "VAX",
        CPU_TYPE_MC680X0 => "MC680x0",
        CPU_TYPE_X86 => "X86",
        CPU_TYPE_MC98000 => "MC98000",
        CPU_TYPE_HPPA => "HPPA",
        CPU_TYPE_ARM => "ARM",
        CPU_TYPE_MC88000 => "MC88000",
        CPU_TYPE_SPARC => "SPARC",
        CPU_TYPE_I860 => "I860",
        CPU_TYPE_POWERPC => "POWERPC",
        CPU_TYPE_POWERPC64 => "POWERPC64",
        CPU_TYPE_X86_64 => "X86_64",
        CPU_TYPE_ARM64 => "ARM64",
        CPU_TYPE_ARM64_32 => "ARM64_32",
        _ => "UNKNOWN",
    }
}

/// Return the bitness of a given cpu type.
pub fn cpu_type_bitness(cpu_type: i32) -> u8 {
    match cpu_type {
        CPU_TYPE_ARM | CPU_TYPE_SPARC | CPU_TYPE_I860 | CPU_TYPE_POWERPC | CPU_TYPE_X86
        | CPU_TYPE_ARM64_32 => 32,
        CPU_TYPE_ARM64 | CPU_TYPE_POWERPC64 | CPU_TYPE_X86_64 => 64,
        _ => {
            if (cpu_type & CPU_ARCH_ABI64) != 0 { 64 } else { 32 }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// CPU Subtypes
// ═══════════════════════════════════════════════════════════════════════════════════════════

// --- PowerPC subtypes ---
pub const CPU_SUBTYPE_POWERPC_ALL: i32 = 0;
pub const CPU_SUBTYPE_POWERPC_601: i32 = 1;
pub const CPU_SUBTYPE_POWERPC_602: i32 = 2;
pub const CPU_SUBTYPE_POWERPC_603: i32 = 3;
pub const CPU_SUBTYPE_POWERPC_603E: i32 = 4;
pub const CPU_SUBTYPE_POWERPC_603EV: i32 = 5;
pub const CPU_SUBTYPE_POWERPC_604: i32 = 6;
pub const CPU_SUBTYPE_POWERPC_604E: i32 = 7;
pub const CPU_SUBTYPE_POWERPC_620: i32 = 8;
pub const CPU_SUBTYPE_POWERPC_750: i32 = 9;
pub const CPU_SUBTYPE_POWERPC_7400: i32 = 10;
pub const CPU_SUBTYPE_POWERPC_7450: i32 = 11;
pub const CPU_SUBTYPE_POWERPC_970: i32 = 100;

// --- x86/x86_64 subtypes ---
/// Build an Intel CPU subtype from family (f) and model (m) values.
pub const fn cpu_subtype_intel(f: i32, m: i32) -> i32 { f + (m << 4) }

pub const CPU_SUBTYPE_I386_ALL: i32 = cpu_subtype_intel(3, 0);
pub const CPU_SUBTYPE_386: i32 = cpu_subtype_intel(3, 0);
pub const CPU_SUBTYPE_486: i32 = cpu_subtype_intel(4, 0);
pub const CPU_SUBTYPE_486SX: i32 = cpu_subtype_intel(4, 8);
pub const CPU_SUBTYPE_586: i32 = cpu_subtype_intel(5, 0);
pub const CPU_SUBTYPE_PENT: i32 = cpu_subtype_intel(5, 0);
pub const CPU_SUBTYPE_PENTPRO: i32 = cpu_subtype_intel(6, 1);
pub const CPU_SUBTYPE_PENTII_M3: i32 = cpu_subtype_intel(6, 3);
pub const CPU_SUBTYPE_PENTII_M5: i32 = cpu_subtype_intel(6, 5);
pub const CPU_SUBTYPE_CELERON: i32 = cpu_subtype_intel(7, 6);
pub const CPU_SUBTYPE_CELERON_MOBILE: i32 = cpu_subtype_intel(7, 7);
pub const CPU_SUBTYPE_PENTIUM_3: i32 = cpu_subtype_intel(8, 0);
pub const CPU_SUBTYPE_PENTIUM_3_M: i32 = cpu_subtype_intel(8, 1);
pub const CPU_SUBTYPE_PENTIUM_3_XEON: i32 = cpu_subtype_intel(8, 2);
pub const CPU_SUBTYPE_PENTIUM_M: i32 = cpu_subtype_intel(9, 0);
pub const CPU_SUBTYPE_PENTIUM_4: i32 = cpu_subtype_intel(10, 0);
pub const CPU_SUBTYPE_PENTIUM_4_M: i32 = cpu_subtype_intel(10, 1);
pub const CPU_SUBTYPE_ITANIUM: i32 = cpu_subtype_intel(11, 0);
pub const CPU_SUBTYPE_ITANIUM_2: i32 = cpu_subtype_intel(11, 1);
pub const CPU_SUBTYPE_XEON: i32 = cpu_subtype_intel(12, 0);
pub const CPU_SUBTYPE_XEON_MP: i32 = cpu_subtype_intel(12, 1);
pub const CPU_SUBTYPE_X86_ALL: i32 = 3;
pub const CPU_SUBTYPE_X86_ARCH1: i32 = 4;
pub const CPU_THREADTYPE_INTEL_HTT: i32 = 1;

// --- ARM subtypes ---
pub const CPU_SUBTYPE_ARM_ALL: i32 = 0;
pub const CPU_SUBTYPE_ARM_V4T: i32 = 5;
pub const CPU_SUBTYPE_ARM_V6: i32 = 6;
pub const CPU_SUBTYPE_ARM_V5: i32 = 7;
pub const CPU_SUBTYPE_ARM_V5TEJ: i32 = 7;
pub const CPU_SUBTYPE_ARM_XSCALE: i32 = 8;
pub const CPU_SUBTYPE_ARM_V7: i32 = 9;
pub const CPU_SUBTYPE_ARM_V7F: i32 = 10;
pub const CPU_SUBTYPE_ARM_V7S: i32 = 11;
pub const CPU_SUBTYPE_ARM_V7K: i32 = 12;
pub const CPU_SUBTYPE_ARM_V6M: i32 = 14;
pub const CPU_SUBTYPE_ARM_V7M: i32 = 15;
pub const CPU_SUBTYPE_ARM_V7EM: i32 = 16;

// --- ARM64 subtypes ---
pub const CPU_SUBTYPE_ARM64_ALL: i32 = 0;
pub const CPU_SUBTYPE_ARM64_V8: i32 = 1;
/// ARM64E (Apple ARM64 with pointer authentication).
pub const CPU_SUBTYPE_ARM64E: i32 = 2;

// --- Misc subtype flags ---
pub const CPU_SUBTYPE_MULTIPLE: i32 = -1;
pub const CPU_SUBTYPE_LITTLE_ENDIAN: i32 = 0;
pub const CPU_SUBTYPE_BIG_ENDIAN: i32 = 1;

// --- SPARC subtypes ---
pub const CPU_SUBTYPE_SPARC_ALL: i32 = 0;

// --- I860 subtypes ---
pub const CPU_SUBTYPE_I860_ALL: i32 = 0;
pub const CPU_SUBTYPE_I860_860: i32 = 1;

// --- MIPS subtypes ---
pub const CPU_SUBTYPE_MIPS_ALL: i32 = 0;
pub const CPU_SUBTYPE_MIPS_R2300: i32 = 1;
pub const CPU_SUBTYPE_MIPS_R2600: i32 = 2;
pub const CPU_SUBTYPE_MIPS_R2800: i32 = 3;

/// Return a human-readable CPU subtype name for a given cpu type and subtype pair.
pub fn cpu_subtype_name(cputype: i32, cpusubtype: i32) -> String {
    match cputype {
        CPU_TYPE_POWERPC | CPU_TYPE_POWERPC64 => match cpusubtype {
            CPU_SUBTYPE_POWERPC_ALL => "ALL".into(),
            CPU_SUBTYPE_POWERPC_601 => "601".into(),
            CPU_SUBTYPE_POWERPC_602 => "602".into(),
            CPU_SUBTYPE_POWERPC_603 => "603".into(),
            CPU_SUBTYPE_POWERPC_603E => "603e".into(),
            CPU_SUBTYPE_POWERPC_603EV => "603ev".into(),
            CPU_SUBTYPE_POWERPC_604 => "604".into(),
            CPU_SUBTYPE_POWERPC_604E => "604e".into(),
            CPU_SUBTYPE_POWERPC_620 => "620".into(),
            CPU_SUBTYPE_POWERPC_750 => "750 (G3)".into(),
            CPU_SUBTYPE_POWERPC_7400 => "7400 (G4)".into(),
            CPU_SUBTYPE_POWERPC_7450 => "7450 (G4+)".into(),
            CPU_SUBTYPE_POWERPC_970 => "970 (G5)".into(),
            _ => format!("UNKNOWN_SUBTYPE({})", cpusubtype),
        },
        CPU_TYPE_X86 | CPU_TYPE_X86_64 => match cpusubtype {
            CPU_SUBTYPE_I386_ALL => "ALL".into(),
            CPU_SUBTYPE_386 => "i386".into(),
            CPU_SUBTYPE_486 => "i486".into(),
            CPU_SUBTYPE_486SX => "i486SX".into(),
            CPU_SUBTYPE_586 => "i586 (Pentium)".into(),
            CPU_SUBTYPE_PENTPRO => "Pentium Pro".into(),
            CPU_SUBTYPE_PENTIUM_3 => "Pentium III".into(),
            CPU_SUBTYPE_PENTIUM_M => "Pentium M".into(),
            CPU_SUBTYPE_PENTIUM_4 => "Pentium 4".into(),
            CPU_SUBTYPE_ITANIUM => "Itanium".into(),
            CPU_SUBTYPE_XEON => "Xeon".into(),
            _ => format!("UNKNOWN_SUBTYPE({})", cpusubtype),
        },
        CPU_TYPE_ARM => match cpusubtype {
            CPU_SUBTYPE_ARM_ALL => "ALL".into(),
            CPU_SUBTYPE_ARM_V4T => "V4T".into(),
            CPU_SUBTYPE_ARM_V6 => "V6".into(),
            CPU_SUBTYPE_ARM_V5 => "V5".into(),
            CPU_SUBTYPE_ARM_XSCALE => "XSCALE".into(),
            CPU_SUBTYPE_ARM_V7 => "V7".into(),
            CPU_SUBTYPE_ARM_V7F => "V7F".into(),
            CPU_SUBTYPE_ARM_V7S => "V7S".into(),
            CPU_SUBTYPE_ARM_V7K => "V7K".into(),
            CPU_SUBTYPE_ARM_V6M => "V6M".into(),
            CPU_SUBTYPE_ARM_V7M => "V7M".into(),
            CPU_SUBTYPE_ARM_V7EM => "V7EM".into(),
            _ => format!("UNKNOWN_SUBTYPE({})", cpusubtype),
        },
        CPU_TYPE_ARM64 => match cpusubtype {
            CPU_SUBTYPE_ARM64_ALL => "ALL".into(),
            CPU_SUBTYPE_ARM64_V8 => "V8".into(),
            CPU_SUBTYPE_ARM64E => "ARM64E".into(),
            _ => format!("UNKNOWN_SUBTYPE({})", cpusubtype),
        },
        _ => format!("{}", cpusubtype),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// File Types
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Relocatable object file.
pub const MH_OBJECT: u32 = 0x1;
/// Demand-paged executable file.
pub const MH_EXECUTE: u32 = 0x2;
/// Fixed VM shared library file.
pub const MH_FVMLIB: u32 = 0x3;
/// Core dump file.
pub const MH_CORE: u32 = 0x4;
/// Preloaded executable file.
pub const MH_PRELOAD: u32 = 0x5;
/// Dynamically bound shared library (dylib).
pub const MH_DYLIB: u32 = 0x6;
/// Dynamic link editor (dyld).
pub const MH_DYLINKER: u32 = 0x7;
/// Dynamically bound bundle file.
pub const MH_BUNDLE: u32 = 0x8;
/// Shared library stub for static linking only (no section contents).
pub const MH_DYLIB_STUB: u32 = 0x9;
/// Debug symbol companion file (dSYM).
pub const MH_DSYM: u32 = 0xa;
/// Kernel extension bundle (x86_64 kexts).
pub const MH_KEXT_BUNDLE: u32 = 0xb;
/// Kernel cache fileset.
pub const MH_FILESET: u32 = 0xc;

/// Return the short name for a file type constant.
pub fn file_type_name(ft: u32) -> &'static str {
    match ft {
        MH_OBJECT => "OBJECT",
        MH_EXECUTE => "EXECUTE",
        MH_FVMLIB => "FVMLIB",
        MH_CORE => "CORE",
        MH_PRELOAD => "PRELOAD",
        MH_DYLIB => "DYLIB",
        MH_DYLINKER => "DYLINKER",
        MH_BUNDLE => "BUNDLE",
        MH_DYLIB_STUB => "DYLIB_STUB",
        MH_DSYM => "DSYM",
        MH_KEXT_BUNDLE => "KEXT_BUNDLE",
        MH_FILESET => "FILESET",
        _ => "UNKNOWN",
    }
}

/// Return a human-readable description for a file type constant.
pub fn file_type_description(ft: u32) -> &'static str {
    match ft {
        MH_OBJECT => "Relocatable Object File",
        MH_EXECUTE => "Demand Paged Executable File",
        MH_FVMLIB => "Fixed VM Shared Library File",
        MH_CORE => "Core File",
        MH_PRELOAD => "Preloaded Executable File",
        MH_DYLIB => "Dynamically Bound Shared Library",
        MH_DYLINKER => "Dynamic Link Editor",
        MH_BUNDLE => "Dynamically Bound Bundle File",
        MH_DYLIB_STUB => "Shared Library Stub for Static Linking Only",
        MH_DSYM => "Companion file with only debug sections",
        MH_KEXT_BUNDLE => "x86_64 Kernel Extension",
        MH_FILESET => "Kernel Cache Fileset",
        _ => "Unrecognized file type",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Header Flags
// ═══════════════════════════════════════════════════════════════════════════════════════════

pub const MH_NOUNDEFS: u32                    = 0x1;
pub const MH_INCRLINK: u32                    = 0x2;
pub const MH_DYLDLINK: u32                    = 0x4;
pub const MH_BINDATLOAD: u32                  = 0x8;
pub const MH_PREBOUND: u32                    = 0x10;
pub const MH_SPLIT_SEGS: u32                  = 0x20;
pub const MH_LAZY_INIT: u32                   = 0x40;
pub const MH_TWOLEVEL: u32                    = 0x80;
pub const MH_FORCE_FLAT: u32                  = 0x100;
pub const MH_NOMULTIDEFS: u32                 = 0x200;
pub const MH_NOFIXPREBINDING: u32             = 0x400;
pub const MH_PREBINDABLE: u32                 = 0x800;
pub const MH_ALLMODSBOUND: u32                = 0x1000;
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32     = 0x2000;
pub const MH_CANONICAL: u32                   = 0x4000;
pub const MH_WEAK_DEFINES: u32                = 0x8000;
pub const MH_BINDS_TO_WEAK: u32               = 0x10000;
pub const MH_ALLOW_STACK_EXECUTION: u32       = 0x20000;
pub const MH_ROOT_SAFE: u32                   = 0x40000;
pub const MH_SETUID_SAFE: u32                 = 0x80000;
pub const MH_NO_REEXPORTED_DYLIBS: u32        = 0x100000;
pub const MH_PIE: u32                         = 0x200000;
pub const MH_DEAD_STRIPPABLE_DYLIB: u32       = 0x400000;
pub const MH_HAS_TLV_DESCRIPTORS: u32         = 0x800000;
pub const MH_NO_HEAP_EXECUTION: u32           = 0x1000000;
pub const MH_APP_EXTENSION_SAFE: u32          = 0x2000000;
pub const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO: u32 = 0x04000000;
pub const MH_SIM_SUPPORT: u32                 = 0x08000000;
pub const MH_DYLIB_IN_CACHE: u32              = 0x80000000;

/// All known header flags with their human-readable names.
pub static HEADER_FLAG_NAMES: &[(u32, &str)] = &[
    (MH_NOUNDEFS, "NOUNDEFS"),
    (MH_INCRLINK, "INCRLINK"),
    (MH_DYLDLINK, "DYLDLINK"),
    (MH_BINDATLOAD, "BINDATLOAD"),
    (MH_PREBOUND, "PREBOUND"),
    (MH_SPLIT_SEGS, "SPLIT_SEGS"),
    (MH_LAZY_INIT, "LAZY_INIT"),
    (MH_TWOLEVEL, "TWOLEVEL"),
    (MH_FORCE_FLAT, "FORCE_FLAT"),
    (MH_NOMULTIDEFS, "NOMULTIDEFS"),
    (MH_NOFIXPREBINDING, "NOFIXPREBINDING"),
    (MH_PREBINDABLE, "PREBINDABLE"),
    (MH_ALLMODSBOUND, "ALLMODSBOUND"),
    (MH_SUBSECTIONS_VIA_SYMBOLS, "SUBSECTIONS_VIA_SYMBOLS"),
    (MH_CANONICAL, "CANONICAL"),
    (MH_WEAK_DEFINES, "WEAK_DEFINES"),
    (MH_BINDS_TO_WEAK, "BINDS_TO_WEAK"),
    (MH_ALLOW_STACK_EXECUTION, "ALLOW_STACK_EXECUTION"),
    (MH_ROOT_SAFE, "ROOT_SAFE"),
    (MH_SETUID_SAFE, "SETUID_SAFE"),
    (MH_NO_REEXPORTED_DYLIBS, "NO_REEXPORTED_DYLIBS"),
    (MH_PIE, "PIE"),
    (MH_DEAD_STRIPPABLE_DYLIB, "DEAD_STRIPPABLE_DYLIB"),
    (MH_HAS_TLV_DESCRIPTORS, "HAS_TLV_DESCRIPTORS"),
    (MH_NO_HEAP_EXECUTION, "NO_HEAP_EXECUTION"),
    (MH_APP_EXTENSION_SAFE, "APP_EXTENSION_SAFE"),
    (MH_NLIST_OUTOFSYNC_WITH_DYLDINFO, "NLIST_OUTOFSYNC_WITH_DYLDINFO"),
    (MH_SIM_SUPPORT, "SIM_SUPPORT"),
    (MH_DYLIB_IN_CACHE, "DYLIB_IN_CACHE"),
];

/// Return the names of all header flags that are set in the given flags value.
pub fn header_flag_names(flags: u32) -> Vec<&'static str> {
    HEADER_FLAG_NAMES
        .iter()
        .filter_map(|&(v, name)| if (flags & v) != 0 { Some(name) } else { None })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Load Command Types
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// If set in a load command, the dynamic linker must understand this command (LC_REQ_DYLD).
pub const LC_REQ_DYLD: u32 = 0x8000_0000;

pub const LC_SEGMENT: u32                  = 0x1;
pub const LC_SYMTAB: u32                   = 0x2;
pub const LC_SYMSEG: u32                   = 0x3;
pub const LC_THREAD: u32                   = 0x4;
pub const LC_UNIXTHREAD: u32               = 0x5;
pub const LC_LOADFVMLIB: u32               = 0x6;
pub const LC_IDFVMLIB: u32                 = 0x7;
pub const LC_IDENT: u32                    = 0x8;
pub const LC_FVMFILE: u32                  = 0x9;
pub const LC_PREPAGE: u32                  = 0xa;
pub const LC_DYSYMTAB: u32                 = 0xb;
pub const LC_LOAD_DYLIB: u32               = 0xc;
pub const LC_ID_DYLIB: u32                 = 0xd;
pub const LC_LOAD_DYLINKER: u32            = 0xe;
pub const LC_ID_DYLINKER: u32              = 0xf;
pub const LC_PREBOUND_DYLIB: u32           = 0x10;
pub const LC_ROUTINES: u32                 = 0x11;
pub const LC_SUB_FRAMEWORK: u32            = 0x12;
pub const LC_SUB_UMBRELLA: u32             = 0x13;
pub const LC_SUB_CLIENT: u32               = 0x14;
pub const LC_SUB_LIBRARY: u32              = 0x15;
pub const LC_TWOLEVEL_HINTS: u32           = 0x16;
pub const LC_PREBIND_CKSUM: u32            = 0x17;
pub const LC_LOAD_WEAK_DYLIB: u32          = 0x18 | LC_REQ_DYLD;
pub const LC_SEGMENT_64: u32               = 0x19;
pub const LC_ROUTINES_64: u32              = 0x1a;
pub const LC_UUID: u32                     = 0x1b;
pub const LC_RPATH: u32                    = 0x1c | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32           = 0x1d;
pub const LC_SEGMENT_SPLIT_INFO: u32       = 0x1e;
pub const LC_REEXPORT_DYLIB: u32           = 0x1f | LC_REQ_DYLD;
pub const LC_LAZY_LOAD_DYLIB: u32          = 0x20;
pub const LC_ENCRYPTION_INFO: u32          = 0x21;
pub const LC_DYLD_INFO: u32                = 0x22;
pub const LC_DYLD_INFO_ONLY: u32           = 0x22 | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32        = 0x23 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32       = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32     = 0x25;
pub const LC_FUNCTION_STARTS: u32          = 0x26;
pub const LC_DYLD_ENVIRONMENT: u32         = 0x27;
pub const LC_MAIN: u32                     = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32             = 0x29;
pub const LC_SOURCE_VERSION: u32           = 0x2a;
pub const LC_DYLIB_CODE_SIGN_DRS: u32     = 0x2b;
pub const LC_ENCRYPTION_INFO_64: u32      = 0x2c;
pub const LC_LINKER_OPTIONS: u32           = 0x2d;
pub const LC_OPTIMIZATION_HINT: u32        = 0x2e;
pub const LC_VERSION_MIN_TVOS: u32         = 0x2f;
pub const LC_VERSION_MIN_WATCHOS: u32      = 0x30;
pub const LC_NOTE: u32                     = 0x31;
pub const LC_BUILD_VERSION: u32            = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32        = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32      = 0x34 | LC_REQ_DYLD;
pub const LC_FILESET_ENTRY: u32            = 0x35 | LC_REQ_DYLD;

// Base command values without LC_REQ_DYLD (for pattern matching).
pub const LC_LOAD_WEAK_DYLIB_BASE: u32     = 0x18;
pub const LC_RPATH_BASE: u32               = 0x1c;
pub const LC_REEXPORT_DYLIB_BASE: u32      = 0x1f;
pub const LC_DYLD_INFO_ONLY_BASE: u32      = 0x22;
pub const LC_LOAD_UPWARD_DYLIB_BASE: u32   = 0x23;
pub const LC_MAIN_BASE: u32                = 0x28;
pub const LC_DYLD_EXPORTS_TRIE_BASE: u32   = 0x33;
pub const LC_DYLD_CHAINED_FIXUPS_BASE: u32 = 0x34;
pub const LC_FILESET_ENTRY_BASE: u32       = 0x35;

/// Return the name of a load command constant.
pub fn load_command_name(cmd: u32) -> String {
    let base = cmd & !LC_REQ_DYLD;
    let name = match base {
        LC_SEGMENT => "LC_SEGMENT",
        LC_SYMTAB => "LC_SYMTAB",
        LC_SYMSEG => "LC_SYMSEG",
        LC_THREAD => "LC_THREAD",
        LC_UNIXTHREAD => "LC_UNIXTHREAD",
        LC_LOADFVMLIB => "LC_LOADFVMLIB",
        LC_IDFVMLIB => "LC_IDFVMLIB",
        LC_IDENT => "LC_IDENT",
        LC_FVMFILE => "LC_FVMFILE",
        LC_PREPAGE => "LC_PREPAGE",
        LC_DYSYMTAB => "LC_DYSYMTAB",
        0xc => "LC_LOAD_DYLIB",
        0xd => "LC_ID_DYLIB",
        0xe => "LC_LOAD_DYLINKER",
        0xf => "LC_ID_DYLINKER",
        LC_PREBOUND_DYLIB => "LC_PREBOUND_DYLIB",
        LC_ROUTINES => "LC_ROUTINES",
        LC_SUB_FRAMEWORK => "LC_SUB_FRAMEWORK",
        LC_SUB_UMBRELLA => "LC_SUB_UMBRELLA",
        LC_SUB_CLIENT => "LC_SUB_CLIENT",
        LC_SUB_LIBRARY => "LC_SUB_LIBRARY",
        LC_TWOLEVEL_HINTS => "LC_TWOLEVEL_HINTS",
        LC_PREBIND_CKSUM => "LC_PREBIND_CKSUM",
        LC_LOAD_WEAK_DYLIB_BASE => "LC_LOAD_WEAK_DYLIB",
        LC_SEGMENT_64 => "LC_SEGMENT_64",
        LC_ROUTINES_64 => "LC_ROUTINES_64",
        LC_UUID => "LC_UUID",
        LC_RPATH_BASE => "LC_RPATH",
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
        LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO",
        LC_REEXPORT_DYLIB_BASE => "LC_REEXPORT_DYLIB",
        LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB",
        LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO",
        LC_DYLD_INFO => "LC_DYLD_INFO",
        LC_DYLD_INFO_ONLY_BASE => "LC_DYLD_INFO_ONLY",
        LC_LOAD_UPWARD_DYLIB_BASE => "LC_LOAD_UPWARD_DYLIB",
        LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
        LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
        LC_DYLD_ENVIRONMENT => "LC_DYLD_ENVIRONMENT",
        LC_MAIN_BASE => "LC_MAIN",
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
        LC_SOURCE_VERSION => "LC_SOURCE_VERSION",
        LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS",
        LC_ENCRYPTION_INFO_64 => "LC_ENCRYPTION_INFO_64",
        LC_LINKER_OPTIONS => "LC_LINKER_OPTIONS",
        LC_OPTIMIZATION_HINT => "LC_OPTIMIZATION_HINT",
        LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS",
        LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS",
        LC_NOTE => "LC_NOTE",
        LC_BUILD_VERSION => "LC_BUILD_VERSION",
        LC_DYLD_EXPORTS_TRIE_BASE => "LC_DYLD_EXPORTS_TRIE",
        LC_DYLD_CHAINED_FIXUPS_BASE => "LC_DYLD_CHAINED_FIXUPS",
        LC_FILESET_ENTRY_BASE => "LC_FILESET_ENTRY",
        _ => "LC_UNKNOWN",
    };
    if name == "LC_UNKNOWN" {
        format!("LC_UNKNOWN_{:#x}", cmd)
    } else {
        name.to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Segment / VM Protection Flags
// ═══════════════════════════════════════════════════════════════════════════════════════════

pub const VM_PROT_NONE: i32    = 0x0;
pub const VM_PROT_READ: i32    = 0x1;
pub const VM_PROT_WRITE: i32   = 0x2;
pub const VM_PROT_EXECUTE: i32 = 0x4;

/// The object file was generated by an Apple-protected segment.
pub const SG_PROTECTED_VERSION_1: u32 = 0x8;

/// Return the protection flags as a human-readable string (e.g., "RWX").
pub fn vm_prot_string(prot: i32) -> String {
    let mut s = String::with_capacity(3);
    if (prot & VM_PROT_READ) != 0    { s.push('R'); }
    if (prot & VM_PROT_WRITE) != 0   { s.push('W'); }
    if (prot & VM_PROT_EXECUTE) != 0 { s.push('X'); }
    if s.is_empty() { s.push_str("NONE"); }
    s
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Section Types and Attributes
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Mask for the section type field (low 8 bits of the flags).
pub const SECTION_TYPE_MASK: u32         = 0x0000_00ff;
/// Mask for the section attributes (upper 24 bits of the flags).
pub const SECTION_ATTRIBUTES_MASK: u32   = 0xffff_ff00;
/// User-settable section attributes.
pub const SECTION_ATTRIBUTES_USR: u32    = 0xff00_0000;
/// System-settable section attributes.
pub const SECTION_ATTRIBUTES_SYS: u32    = 0x00ff_ff00;

// --- Section types (low 8 bits of flags) ---
pub const S_REGULAR: u32                             = 0x0;
pub const S_ZEROFILL: u32                            = 0x1;
pub const S_CSTRING_LITERALS: u32                    = 0x2;
pub const S_4BYTE_LITERALS: u32                      = 0x3;
pub const S_8BYTE_LITERALS: u32                      = 0x4;
pub const S_LITERAL_POINTERS: u32                    = 0x5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32            = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u32                = 0x7;
pub const S_SYMBOL_STUBS: u32                        = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u32              = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u32              = 0xa;
pub const S_COALESCED: u32                           = 0xb;
pub const S_GB_ZEROFILL: u32                         = 0xc;
pub const S_INTERPOSING: u32                         = 0xd;
pub const S_16BYTE_LITERALS: u32                     = 0xe;
pub const S_DTRACE_DOF: u32                          = 0xf;
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32          = 0x10;
pub const S_THREAD_LOCAL_REGULAR: u32                = 0x11;
pub const S_THREAD_LOCAL_ZEROFILL: u32               = 0x12;
pub const S_THREAD_LOCAL_VARIABLES: u32              = 0x13;
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32      = 0x14;
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;

// --- Section attributes (upper 24 bits of flags) ---
pub const S_ATTR_PURE_INSTRUCTIONS: u32   = 0x8000_0000;
pub const S_ATTR_NO_TOC: u32              = 0x4000_0000;
pub const S_ATTR_STRIP_STATIC_SYMS: u32   = 0x2000_0000;
pub const S_ATTR_NO_DEAD_STRIP: u32       = 0x1000_0000;
pub const S_ATTR_LIVE_SUPPORT: u32        = 0x0800_0000;
pub const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x0400_0000;
pub const S_ATTR_DEBUG: u32               = 0x0200_0000;
pub const S_ATTR_SOME_INSTRUCTIONS: u32   = 0x0000_0400;
pub const S_ATTR_EXT_RELOC: u32           = 0x0000_0200;
pub const S_ATTR_LOC_RELOC: u32           = 0x0000_0100;

/// Return the name of a section type (low 8 bits of the flags field).
pub fn section_type_name(t: u32) -> String {
    match t {
        S_REGULAR => "REGULAR".into(),
        S_ZEROFILL => "ZEROFILL".into(),
        S_CSTRING_LITERALS => "CSTRING_LITERALS".into(),
        S_4BYTE_LITERALS => "4BYTE_LITERALS".into(),
        S_8BYTE_LITERALS => "8BYTE_LITERALS".into(),
        S_LITERAL_POINTERS => "LITERAL_POINTERS".into(),
        S_NON_LAZY_SYMBOL_POINTERS => "NON_LAZY_SYMBOL_POINTERS".into(),
        S_LAZY_SYMBOL_POINTERS => "LAZY_SYMBOL_POINTERS".into(),
        S_SYMBOL_STUBS => "SYMBOL_STUBS".into(),
        S_MOD_INIT_FUNC_POINTERS => "MOD_INIT_FUNC_POINTERS".into(),
        S_MOD_TERM_FUNC_POINTERS => "MOD_TERM_FUNC_POINTERS".into(),
        S_COALESCED => "COALESCED".into(),
        S_GB_ZEROFILL => "GB_ZEROFILL".into(),
        S_INTERPOSING => "INTERPOSING".into(),
        S_16BYTE_LITERALS => "16BYTE_LITERALS".into(),
        S_DTRACE_DOF => "DTRACE_DOF".into(),
        S_LAZY_DYLIB_SYMBOL_POINTERS => "LAZY_DYLIB_SYMBOL_POINTERS".into(),
        S_THREAD_LOCAL_REGULAR => "THREAD_LOCAL_REGULAR".into(),
        S_THREAD_LOCAL_ZEROFILL => "THREAD_LOCAL_ZEROFILL".into(),
        S_THREAD_LOCAL_VARIABLES => "THREAD_LOCAL_VARIABLES".into(),
        S_THREAD_LOCAL_VARIABLE_POINTERS => "THREAD_LOCAL_VARIABLE_POINTERS".into(),
        S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => "THREAD_LOCAL_INIT_FUNCTION_POINTERS".into(),
        _ => format!("UNKNOWN_SECTION_TYPE_{:#x}", t),
    }
}

/// Return the names of known section attributes set in the given flags.
pub fn section_attribute_names(flags: u32) -> Vec<&'static str> {
    let mut names = Vec::new();
    if (flags & S_ATTR_PURE_INSTRUCTIONS) != 0   { names.push("PURE_INSTRUCTIONS"); }
    if (flags & S_ATTR_NO_TOC) != 0              { names.push("NO_TOC"); }
    if (flags & S_ATTR_STRIP_STATIC_SYMS) != 0   { names.push("STRIP_STATIC_SYMS"); }
    if (flags & S_ATTR_NO_DEAD_STRIP) != 0       { names.push("NO_DEAD_STRIP"); }
    if (flags & S_ATTR_LIVE_SUPPORT) != 0        { names.push("LIVE_SUPPORT"); }
    if (flags & S_ATTR_SELF_MODIFYING_CODE) != 0 { names.push("SELF_MODIFYING_CODE"); }
    if (flags & S_ATTR_DEBUG) != 0               { names.push("DEBUG"); }
    if (flags & S_ATTR_SOME_INSTRUCTIONS) != 0   { names.push("SOME_INSTRUCTIONS"); }
    if (flags & S_ATTR_EXT_RELOC) != 0           { names.push("EXT_RELOC"); }
    if (flags & S_ATTR_LOC_RELOC) != 0           { names.push("LOC_RELOC"); }
    names
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// NList (Symbol Table) Constants
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Mask for debug (STAB) symbol bits.
pub const N_STAB: u8 = 0xe0;
/// Private external symbol bit.
pub const N_PEXT: u8 = 0x10;
/// Mask for the symbol type bits.
pub const N_TYPE: u8 = 0x0e;
/// External symbol bit (global).
pub const N_EXT: u8  = 0x01;

/// Undefined symbol type.
pub const N_UNDF: u8 = 0x0;
/// Absolute symbol type.
pub const N_ABS: u8  = 0x2;
/// Symbol defined in a section.
pub const N_SECT: u8 = 0xe;
/// Prebound undefined symbol.
pub const N_PBUD: u8 = 0xc;
/// Indirect symbol.
pub const N_INDR: u8 = 0xa;

/// Symbol is not in any section.
pub const NO_SECT: u8 = 0;

// --- n_desc reference flags ---
pub const REFERENCE_TYPE: u16                          = 0x7;
pub const REFERENCE_FLAG_UNDEFINED_NON_LAZY: u16       = 0x0;
pub const REFERENCE_FLAG_UNDEFINED_LAZY: u16           = 0x1;
pub const REFERENCE_FLAG_DEFINED: u16                  = 0x2;
pub const REFERENCE_FLAG_PRIVATE_DEFINED: u16          = 0x3;
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY: u16 = 0x4;
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY: u16   = 0x5;
pub const REFERENCED_DYNAMICALLY: u16                  = 0x0010;
pub const N_DESC_DISCARDED: u16                        = 0x0020;
pub const N_WEAK_REF: u16                              = 0x0040;
pub const N_WEAK_DEF: u16                              = 0x0080;
pub const N_REF_TO_WEAK: u16                           = 0x0080;
pub const N_ARM_THUMB_DEF: u16                         = 0x0008;

// --- Library ordinals ---
pub const SELF_LIBRARY_ORDINAL: u8    = 0x00;
pub const MAX_LIBRARY_ORDINAL: u8     = 0xfd;
pub const DYNAMIC_LOOKUP_ORDINAL: u8  = 0xfe;
pub const EXECUTABLE_ORDINAL: u8      = 0xff;

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Dynamic Symbol Table Constants
// ═══════════════════════════════════════════════════════════════════════════════════════════

pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
pub const INDIRECT_SYMBOL_ABS: u32   = 0x4000_0000;

// ═══════════════════════════════════════════════════════════════════════════════════════════
// DYLD Rebase / Bind Opcode Constants
// ═══════════════════════════════════════════════════════════════════════════════════════════

// --- Rebase ---
pub const REBASE_TYPE_POINTER: u8         = 1;
pub const REBASE_TYPE_TEXT_ABSOLUTE32: u8  = 2;
pub const REBASE_TYPE_TEXT_PCREL32: u8     = 3;

pub const REBASE_OPCODE_MASK: u8              = 0xF0;
pub const REBASE_IMMEDIATE_MASK: u8           = 0x0F;
pub const REBASE_OPCODE_DONE: u8                                 = 0x00;
pub const REBASE_OPCODE_SET_TYPE_IMM: u8                         = 0x10;
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8          = 0x20;
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8                        = 0x30;
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8                  = 0x40;
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8                  = 0x50;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8                 = 0x60;
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8              = 0x70;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8   = 0x80;

// --- Bind ---
pub const BIND_TYPE_POINTER: u8          = 1;
pub const BIND_TYPE_TEXT_ABSOLUTE32: u8   = 2;
pub const BIND_TYPE_TEXT_PCREL32: u8      = 3;

pub const BIND_SPECIAL_DYLIB_SELF: i64             = 0;
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i64   = -1;
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i64       = -2;
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: i64       = -3;

pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8          = 0x1;
pub const BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: u8  = 0x8;

pub const BIND_OPCODE_MASK: u8     = 0xF0;
pub const BIND_IMMEDIATE_MASK: u8  = 0x0F;
pub const BIND_OPCODE_DONE: u8                                   = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8                  = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8                 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8                  = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8          = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8                           = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8                        = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8            = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8                          = 0x80;
pub const BIND_OPCODE_DO_BIND: u8                                = 0x90;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8                  = 0xA0;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8            = 0xB0;
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8      = 0xC0;
pub const BIND_OPCODE_THREADED: u8                               = 0xD0;
pub const BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: u8 = 0x00;
pub const BIND_SUBOPCODE_THREADED_APPLY: u8                      = 0x01;

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Export Symbol Flags
// ═══════════════════════════════════════════════════════════════════════════════════════════

pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64          = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64       = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64  = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64      = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64    = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64           = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64  = 0x10;

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Build Version Platforms
// ═══════════════════════════════════════════════════════════════════════════════════════════

pub const PLATFORM_MACOS: u32              = 1;
pub const PLATFORM_IOS: u32                = 2;
pub const PLATFORM_TVOS: u32               = 3;
pub const PLATFORM_WATCHOS: u32            = 4;
pub const PLATFORM_BRIDGEOS: u32           = 5;
pub const PLATFORM_MACCATALYST: u32        = 6;
pub const PLATFORM_IOSSIMULATOR: u32       = 7;
pub const PLATFORM_TVOSSIMULATOR: u32      = 8;
pub const PLATFORM_WATCHOSSIMULATOR: u32   = 9;
pub const PLATFORM_DRIVERKIT: u32          = 10;
pub const PLATFORM_VISIONOS: u32           = 11;
pub const PLATFORM_VISIONOSSIMULATOR: u32  = 12;

/// Return the name of a build platform constant.
pub fn platform_name(platform: u32) -> &'static str {
    match platform {
        PLATFORM_MACOS => "MACOS",
        PLATFORM_IOS => "IOS",
        PLATFORM_TVOS => "TVOS",
        PLATFORM_WATCHOS => "WATCHOS",
        PLATFORM_BRIDGEOS => "BRIDGEOS",
        PLATFORM_MACCATALYST => "MACCATALYST",
        PLATFORM_IOSSIMULATOR => "IOSSIMULATOR",
        PLATFORM_TVOSSIMULATOR => "TVOSSIMULATOR",
        PLATFORM_WATCHOSSIMULATOR => "WATCHOSSIMULATOR",
        PLATFORM_DRIVERKIT => "DRIVERKIT",
        PLATFORM_VISIONOS => "VISIONOS",
        PLATFORM_VISIONOSSIMULATOR => "VISIONOSSIMULATOR",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Build Tools
// ═══════════════════════════════════════════════════════════════════════════════════════════

pub const TOOL_CLANG: u32 = 1;
pub const TOOL_SWIFT: u32 = 2;
pub const TOOL_LD: u32    = 3;
pub const TOOL_LLD: u32   = 4;

/// Return the name of a build tool constant.
pub fn tool_name(tool: u32) -> &'static str {
    match tool {
        TOOL_CLANG => "CLANG",
        TOOL_SWIFT => "SWIFT",
        TOOL_LD => "LD",
        TOOL_LLD => "LLD",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Code Signature Magic Constants
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// The embedded code signature requirement (single requirement blob).
pub const CSMAGIC_REQUIREMENT: u32     = 0xfade0c00;
/// The embedded code signature requirements (requirements vector).
pub const CSMAGIC_REQUIREMENTS: u32    = 0xfade0c01;
/// The embedded code signature (single code directory).
pub const CSMAGIC_CODEDIRECTORY: u32   = 0xfade0c02;
/// The embedded entitlements XML blob.
pub const CSMAGIC_ENTITLEMENTS: u32    = 0xfade7171;
/// The wrapper embedding a full superset of blobs on one superblob.
pub const CSMAGIC_BLOBWRAPPER: u32     = 0xfade0b01;
/// The embedded signature blob (detached code signature data).
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
/// Multi-arch detached signature.
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade0cc1;
/// Code signing data with explicit code directory hash type.
pub const CSMAGIC_CODEDIRECTORY_V2: u32 = 0xfade0c02;
/// CMS (RFC 5652) blob used for code signing.
pub const CSMAGIC_CMS_BLOB: u32         = 0xfade0b02;

/// Return the name of a code signature magic value.
pub fn cs_magic_name(magic: u32) -> &'static str {
    match magic {
        CSMAGIC_REQUIREMENT => "CSMAGIC_REQUIREMENT",
        CSMAGIC_REQUIREMENTS => "CSMAGIC_REQUIREMENTS",
        CSMAGIC_CODEDIRECTORY => "CSMAGIC_CODEDIRECTORY",
        CSMAGIC_ENTITLEMENTS => "CSMAGIC_ENTITLEMENTS",
        CSMAGIC_BLOBWRAPPER => "CSMAGIC_BLOBWRAPPER",
        CSMAGIC_EMBEDDED_SIGNATURE => "CSMAGIC_EMBEDDED_SIGNATURE",
        CSMAGIC_DETACHED_SIGNATURE => "CSMAGIC_DETACHED_SIGNATURE",
        CSMAGIC_CMS_BLOB => "CSMAGIC_CMS_BLOB",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Chained Fixups Pointer Format Constants
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// The start of a chained fixups pointer chain.
pub const DYLD_CHAINED_PTR_START: u16   = 0xFFFF;
/// Chained pointer has a bind information.
pub const DYLD_CHAINED_PTR_ARM64E_BIND: u16 = 0x00E1;
/// Chained pointer is an authenticated rebase.
pub const DYLD_CHAINED_PTR_ARM64E_AUTH_REBASE: u16 = 0x00E2;
/// Chained pointer is a rebase (no authentication).
pub const DYLD_CHAINED_PTR_ARM64E_REBASE: u16 = 0x00E3;
/// Chained pointer is an authenticated bind.
pub const DYLD_CHAINED_PTR_ARM64E_AUTH_BIND: u16 = 0x00E4;
/// Chained pointer is the next frame to walk.
pub const DYLD_CHAINED_PTR_ARM64E_NEXT: u16 = 0x00E5;

/// Chained pointer format: generic 64-bit (used for older arm64e).
pub const DYLD_CHAINED_PTR_64: u16             = 4;
/// Chained pointer format: 64-bit offset.
pub const DYLD_CHAINED_PTR_64_OFFSET: u16       = 6;
/// Chained pointer format: arm64e authenticated.
pub const DYLD_CHAINED_PTR_ARM64E: u16          = 7;
/// Chained pointer format: arm64e authenticated with kernel cache.
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16   = 8;
/// Chained pointer format: arm64e userland24.
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 9;
/// Chained pointer format: arm64e shared cache.
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
/// Chained pointer format: x86_64 userland.
pub const DYLD_CHAINED_PTR_X86_64_USERLAND: u16 = 12;

/// Return the name for a chained pointer format.
pub fn chained_ptr_format_name(format: u16) -> &'static str {
    match format {
        DYLD_CHAINED_PTR_64 => "PTR_64",
        DYLD_CHAINED_PTR_64_OFFSET => "PTR_64_OFFSET",
        DYLD_CHAINED_PTR_ARM64E => "PTR_ARM64E",
        DYLD_CHAINED_PTR_ARM64E_KERNEL => "PTR_ARM64E_KERNEL",
        DYLD_CHAINED_PTR_ARM64E_USERLAND24 => "PTR_ARM64E_USERLAND24",
        DYLD_CHAINED_PTR_ARM64E_FIRMWARE => "PTR_ARM64E_FIRMWARE",
        DYLD_CHAINED_PTR_X86_64_USERLAND => "PTR_X86_64_USERLAND",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Error Type
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Errors that can occur during Mach-O and FAT parsing.
#[derive(Debug, Clone)]
pub enum MachError {
    /// The magic number does not match any known Mach-O or FAT magic.
    InvalidMagic(u32),
    /// The header is structurally invalid or inconsistent.
    InvalidHeader,
    /// Too many load commands (sanity limit exceeded).
    TooManyCommands,
    /// A load command has an invalid or inconsistent size field.
    InvalidCommandSize,
    /// The data is shorter than expected / truncated.
    TruncatedData,
    /// An embedded string could not be parsed.
    InvalidString,
    /// A ULEB128 or SLEB128 value could not be decoded.
    InvalidULEB,
    /// The export trie structure is invalid.
    InvalidExportTrie,
    /// A circular reference was detected in the export trie.
    CircularExportTrie,
    /// The code signature blob is malformed.
    InvalidCodeSignature,
    /// A nom combinator returned an error.
    NomError(String),
}

impl fmt::Display for MachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachError::InvalidMagic(m) => write!(f, "Invalid Mach-O magic: 0x{:08x}", m),
            MachError::InvalidHeader => write!(f, "Invalid Mach-O header"),
            MachError::TooManyCommands => write!(f, "Too many load commands"),
            MachError::InvalidCommandSize => write!(f, "Invalid load command size"),
            MachError::TruncatedData => write!(f, "Truncated data"),
            MachError::InvalidString => write!(f, "Invalid string in binary"),
            MachError::InvalidULEB => write!(f, "Invalid ULEB128 / SLEB128 encoding"),
            MachError::InvalidExportTrie => write!(f, "Invalid export trie structure"),
            MachError::CircularExportTrie => write!(f, "Circular reference in export trie"),
            MachError::InvalidCodeSignature => write!(f, "Invalid code signature blob"),
            MachError::NomError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for MachError {}

impl From<nom::Err<nom::error::Error<&[u8]>>> for MachError {
    fn from(e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        MachError::NomError(format!("{:?}", e))
    }
}

/// Type alias for Mach-O parse results.
pub type MachResult<T> = Result<T, MachError>;

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Read a NUL-padded string from a byte slice up to max_len bytes wide.
/// Stops at the first NUL byte or max_len, whichever comes first.
fn read_padded_string(data: &[u8], max_len: usize) -> String {
    let end = data
        .iter()
        .take(max_len)
        .position(|&b| b == 0)
        .unwrap_or(max_len);
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Decode a ULEB128 value from bytes.
/// Returns (value, bytes_consumed).
fn decode_uleb128(data: &[u8]) -> MachResult<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(MachError::InvalidULEB);
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(MachError::InvalidULEB)
}

/// Decode an SLEB128 value from bytes.
/// Returns (value, bytes_consumed).
fn decode_sleb128(data: &[u8]) -> MachResult<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut byte: u8 = 0;
    for (i, &b) in data.iter().enumerate() {
        if i >= 10 {
            return Err(MachError::InvalidULEB);
        }
        byte = b;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= -(1i64 << shift);
    }
    let mut consumed = 1;
    for &b in data.iter() {
        if b & 0x80 == 0 {
            break;
        }
        consumed += 1;
    }
    Ok((result, consumed))
}

/// Convenience: read a NUL-terminated string from a given offset within `data`.
fn read_cstring(data: &[u8], start: usize) -> String {
    if start >= data.len() {
        return String::new();
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - start);
    String::from_utf8_lossy(&data[start..start + end]).to_string()
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Data Structures
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// A FAT (universal) binary container.
///
/// FAT binaries contain multiple Mach-O files, each targeting a different
/// CPU architecture. This allows a single file to run on multiple platforms.
#[derive(Debug, Clone)]
pub struct FatBinary {
    /// The list of architecture entries contained in the FAT binary.
    pub arches: Vec<FatArch>,
}

impl FatBinary {
    /// Find the architecture entry matching a given CPU type.
    /// Returns None if no matching architecture is found.
    pub fn find_arch(&self, cputype: i32) -> Option<&FatArch> {
        self.arches.iter().find(|a| a.cputype == cputype)
    }

    /// Return the number of architectures in the FAT binary.
    pub fn num_arches(&self) -> usize {
        self.arches.len()
    }

    /// Return all unique CPU types found in the FAT binary.
    pub fn cpu_types(&self) -> Vec<i32> {
        let mut types: Vec<i32> = self.arches.iter().map(|a| a.cputype).collect();
        types.sort();
        types.dedup();
        types
    }
}

/// A single architecture entry within a FAT binary.
///
/// Each entry describes the CPU type, layout offset, size, and required
/// power-of-2 alignment for one slice of the universal binary.
#[derive(Debug, Clone)]
pub struct FatArch {
    /// CPU type (see CPU_TYPE_* constants).
    pub cputype: i32,
    /// CPU subtype (see CPU_SUBTYPE_* constants).
    pub cpusubtype: i32,
    /// Byte offset from the start of the FAT binary to the embedded Mach-O slice.
    pub offset: u32,
    /// Size in bytes of the embedded Mach-O slice.
    pub size: u32,
    /// Required power-of-2 alignment for this slice (e.g., 12 = 4096).
    pub align: u32,
}

impl FatArch {
    /// Return the human-readable CPU type name.
    pub fn cpu_name(&self) -> &'static str {
        cpu_type_name(self.cputype)
    }

    /// Return the human-readable CPU subtype name.
    pub fn cpu_subtype_name(&self) -> String {
        cpu_subtype_name(self.cputype, self.cpusubtype)
    }

    /// Return the bitness of the architecture (32 or 64).
    pub fn bitness(&self) -> u8 {
        cpu_type_bitness(self.cputype)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// MachOFile
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// The complete parsed Mach-O file.
///
/// This is the main return value of `parse_macho`. All 32-bit numeric
/// fields are promoted to u64 on read for uniform access.
#[derive(Debug, Clone)]
pub struct MachOFile {
    /// The Mach-O header.
    pub header: MachHeader,
    /// All parsed load commands, in the order they appear in the file.
    pub commands: Vec<LoadCommand>,
    /// All sections extracted from LC_SEGMENT / LC_SEGMENT_64 commands.
    pub sections: Vec<Section>,
    /// All symbol table entries (NList / NList64).
    pub symbols: Vec<NList>,
    /// The raw string table bytes.
    pub strings: Vec<u8>,
}

impl MachOFile {
    // ── Segment access ──

    /// Return all LC_SEGMENT_64 load commands.
    pub fn segments(&self) -> Vec<&SegmentCommand> {
        self.commands
            .iter()
            .filter_map(|c| match c {
                LoadCommand::Segment64(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    /// Find a named segment.
    pub fn segment(&self, name: &str) -> Option<&SegmentCommand> {
        self.segments().into_iter().find(|s| s.segname == name)
    }

    /// Return segment base addresses for use in binding address resolution.
    pub fn segment_base_addresses(&self) -> Vec<u64> {
        self.segments().iter().map(|s| s.vmaddr).collect()
    }

    // ── General command access ──

    /// Find the UUID load command.
    pub fn uuid(&self) -> Option<&UuidCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::Uuid(u) => Some(u),
            _ => None,
        })
    }

    /// Find the symbol table command.
    pub fn symtab(&self) -> Option<&SymtabCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::Symtab(s) => Some(s),
            _ => None,
        })
    }

    /// Find the dynamic symbol table command.
    pub fn dysymtab(&self) -> Option<&DysymtabCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::Dysymtab(d) => Some(d),
            _ => None,
        })
    }

    /// Find the dyld info command.
    pub fn dyld_info(&self) -> Option<&DyldInfoCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::DyldInfo(d) => Some(d),
            _ => None,
        })
    }

    /// Find the build version command.
    pub fn build_version(&self) -> Option<&BuildVersionCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::BuildVersion(b) => Some(b),
            _ => None,
        })
    }

    /// Find the entry point (LC_MAIN).
    pub fn main(&self) -> Option<&MainCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::Main(m) => Some(m),
            _ => None,
        })
    }

    /// Find the code signature linkedit data command.
    pub fn code_signature(&self) -> Option<&LinkeditDataCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::CodeSignature(cs) => Some(cs),
            _ => None,
        })
    }

    /// Find the dyld exports trie linkedit data command.
    pub fn dyld_exports_trie(&self) -> Option<&LinkeditDataCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::DyldExportsTrie(d) => Some(d),
            _ => None,
        })
    }

    /// Find the dyld chained fixups linkedit data command.
    pub fn dyld_chained_fixups(&self) -> Option<&LinkeditDataCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::DyldChainedFixups(d) => Some(d),
            _ => None,
        })
    }

    // ── Dylib access ──

    /// Return all LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, and LC_REEXPORT_DYLIB entries.
    pub fn dylibs(&self) -> Vec<&DylibCommand> {
        self.commands
            .iter()
            .filter_map(|c| match c {
                LoadCommand::LoadDylib(d)
                | LoadCommand::LoadWeakDylib(d)
                | LoadCommand::ReexportDylib(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    /// Find a dylib by name (e.g., "/usr/lib/libSystem.B.dylib").
    pub fn find_dylib(&self, name: &str) -> Option<&DylibCommand> {
        self.dylibs().into_iter().find(|d| d.name == name)
    }

    /// Return all RPATH entries.
    pub fn rpaths(&self) -> Vec<&RpathCommand> {
        self.commands
            .iter()
            .filter_map(|c| match c {
                LoadCommand::Rpath(r) => Some(r),
                _ => None,
            })
            .collect()
    }

    /// Return the entry point (file offset) if LC_MAIN is present.
    pub fn entry_point(&self) -> Option<u64> {
        self.main().map(|m| m.entryoff)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// MachHeader
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// The Mach-O header (mach_header or mach_header_64).
///
/// For 32-bit files the `reserved` field is always zero.
#[derive(Debug, Clone)]
pub struct MachHeader {
    /// The original magic number from the file.
    pub magic: u32,
    /// CPU type (see CPU_TYPE_*).
    pub cputype: i32,
    /// CPU subtype (see CPU_SUBTYPE_*).
    pub cpusubtype: i32,
    /// File type (see MH_* constants).
    pub filetype: u32,
    /// Number of load commands following the header.
    pub ncmds: u32,
    /// Total size in bytes of all load commands.
    pub sizeofcmds: u32,
    /// Header flags bitfield (see MH_* flags).
    pub flags: u32,
    /// Reserved field (only present in mach_header_64, zero otherwise).
    pub reserved: u32,
}

impl MachHeader {
    /// True if the magic indicates a 64-bit Mach-O binary.
    pub fn is_64bit(&self) -> bool { is_macho_64(self.magic) }

    /// True if the magic indicates a little-endian Mach-O binary.
    pub fn is_le(&self) -> bool { is_macho_le(self.magic) }

    /// Return the bitness: 64 or 32.
    pub fn bitness(&self) -> u8 {
        if self.is_64bit() { 64 } else { 32 }
    }

    /// Return the CPU type name (e.g., "ARM64").
    pub fn cpu_name(&self) -> &'static str {
        cpu_type_name(self.cputype)
    }

    /// Return the CPU subtype name.
    pub fn cpu_subtype_name(&self) -> String {
        cpu_subtype_name(self.cputype, self.cpusubtype)
    }

    /// Return the file type name (e.g., "EXECUTE").
    pub fn file_type_name(&self) -> &'static str {
        file_type_name(self.filetype)
    }

    /// Return the file type description.
    pub fn file_type_desc(&self) -> &'static str {
        file_type_description(self.filetype)
    }

    /// True if this is a dylib (MH_DYLIB).
    pub fn is_dylib(&self) -> bool { self.filetype == MH_DYLIB }

    /// True if this is an executable (MH_EXECUTE).
    pub fn is_executable(&self) -> bool { self.filetype == MH_EXECUTE }

    /// True if this is a dSYM file (MH_DSYM).
    pub fn is_dsym(&self) -> bool { self.filetype == MH_DSYM }

    /// Return the names of all set header flags.
    pub fn flag_names(&self) -> Vec<&'static str> {
        header_flag_names(self.flags)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// LoadCommand
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// All recognised load commands.
///
/// Unknown commands are preserved as `Unknown` containing the raw cmd,
/// cmdsize, and the full command data.
#[derive(Debug, Clone)]
pub enum LoadCommand {
    /// LC_SEGMENT_64: 64-bit segment command.
    Segment64(SegmentCommand),
    /// LC_SYMTAB: Symbol table command.
    Symtab(SymtabCommand),
    /// LC_DYSYMTAB: Dynamic symbol table command.
    Dysymtab(DysymtabCommand),
    /// A generic dylib command (historical, not used in Dispatch).
    Dylib(DylibCommand),
    /// LC_LOAD_DYLIB: Load a dylib.
    LoadDylib(DylibCommand),
    /// LC_ID_DYLIB: Declare the dylib's own identity.
    IdDylib(DylibCommand),
    /// LC_LOAD_WEAK_DYLIB: Load a dylib optionally (weak).
    LoadWeakDylib(DylibCommand),
    /// LC_REEXPORT_DYLIB: Re-export symbols from another dylib.
    ReexportDylib(DylibCommand),
    /// LC_LOAD_DYLINKER / LC_ID_DYLINKER: Dylinker path.
    Dylinker(DylinkerCommand),
    /// LC_UUID: 128-bit UUID.
    Uuid(UuidCommand),
    /// LC_VERSION_MIN_MACOSX / LC_VERSION_MIN_IPHONEOS / etc.
    VersionMin(VersionMinCommand),
    /// LC_SOURCE_VERSION: Source version.
    SourceVersion(SourceVersionCommand),
    /// LC_MAIN: Entry point.
    Main(MainCommand),
    /// LC_RPATH: Run-path addition.
    Rpath(RpathCommand),
    /// LC_CODE_SIGNATURE: Code signature linkedit data.
    CodeSignature(LinkeditDataCommand),
    /// LC_SEGMENT_SPLIT_INFO: Segment split info linkedit data.
    SegmentSplitInfo(LinkeditDataCommand),
    /// LC_FUNCTION_STARTS: Function starts linkedit data.
    FunctionStarts(LinkeditDataCommand),
    /// LC_DATA_IN_CODE: Data-in-code linkedit data.
    DataInCode(LinkeditDataCommand),
    /// LC_DYLD_INFO / LC_DYLD_INFO_ONLY.
    DyldInfo(DyldInfoCommand),
    /// LC_DYLD_EXPORTS_TRIE: Export trie linkedit data.
    DyldExportsTrie(LinkeditDataCommand),
    /// LC_DYLD_CHAINED_FIXUPS: Chained fixups linkedit data.
    DyldChainedFixups(LinkeditDataCommand),
    /// LC_BUILD_VERSION: Build version with tools.
    BuildVersion(BuildVersionCommand),
    /// LC_DYLD_ENVIRONMENT: Dyld environment variable.
    DyldEnvironment(DyldEnvironmentCommand),
    /// LC_ENCRYPTION_INFO: 32-bit encryption info.
    EncryptionInfo(EncryptionInfoCommand),
    /// LC_ENCRYPTION_INFO_64: 64-bit encryption info.
    EncryptionInfo64(EncryptionInfoCommand),
    /// LC_LINKER_OPTIONS: Linker option strings.
    LinkerOption(LinkerOptionCommand),
    /// LC_FILESET_ENTRY: Kernel fileset entry.
    FilesetEntry(FilesetEntryCommand),
    /// LC_NOTE: Note / remark.
    Note(NoteCommand),
    /// An unrecognised load command (raw data preserved).
    Unknown {
        /// The raw command type.
        cmd: u32,
        /// The total command size in bytes.
        cmdsize: u32,
        /// The raw command bytes.
        data: Vec<u8>,
    },
}

impl LoadCommand {
    /// Return the human-readable name for this load command variant.
    pub fn name(&self) -> String {
        match self {
            LoadCommand::Segment64(_) => "LC_SEGMENT_64".into(),
            LoadCommand::Symtab(_) => "LC_SYMTAB".into(),
            LoadCommand::Dysymtab(_) => "LC_DYSYMTAB".into(),
            LoadCommand::Dylib(_) => "LC_LOAD_DYLIB".into(),
            LoadCommand::LoadDylib(_) => "LC_LOAD_DYLIB".into(),
            LoadCommand::IdDylib(_) => "LC_ID_DYLIB".into(),
            LoadCommand::LoadWeakDylib(_) => "LC_LOAD_WEAK_DYLIB".into(),
            LoadCommand::ReexportDylib(_) => "LC_REEXPORT_DYLIB".into(),
            LoadCommand::Dylinker(_) => "LC_LOAD_DYLINKER".into(),
            LoadCommand::Uuid(_) => "LC_UUID".into(),
            LoadCommand::VersionMin(_) => "LC_VERSION_MIN_*".into(),
            LoadCommand::SourceVersion(_) => "LC_SOURCE_VERSION".into(),
            LoadCommand::Main(_) => "LC_MAIN".into(),
            LoadCommand::Rpath(_) => "LC_RPATH".into(),
            LoadCommand::CodeSignature(_) => "LC_CODE_SIGNATURE".into(),
            LoadCommand::SegmentSplitInfo(_) => "LC_SEGMENT_SPLIT_INFO".into(),
            LoadCommand::FunctionStarts(_) => "LC_FUNCTION_STARTS".into(),
            LoadCommand::DataInCode(_) => "LC_DATA_IN_CODE".into(),
            LoadCommand::DyldInfo(_) => "LC_DYLD_INFO".into(),
            LoadCommand::DyldExportsTrie(_) => "LC_DYLD_EXPORTS_TRIE".into(),
            LoadCommand::DyldChainedFixups(_) => "LC_DYLD_CHAINED_FIXUPS".into(),
            LoadCommand::BuildVersion(_) => "LC_BUILD_VERSION".into(),
            LoadCommand::DyldEnvironment(_) => "LC_DYLD_ENVIRONMENT".into(),
            LoadCommand::EncryptionInfo(_) => "LC_ENCRYPTION_INFO".into(),
            LoadCommand::EncryptionInfo64(_) => "LC_ENCRYPTION_INFO_64".into(),
            LoadCommand::LinkerOption(_) => "LC_LINKER_OPTIONS".into(),
            LoadCommand::FilesetEntry(_) => "LC_FILESET_ENTRY".into(),
            LoadCommand::Note(_) => "LC_NOTE".into(),
            LoadCommand::Unknown { cmd, .. } => load_command_name(*cmd),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SegmentCommand
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Segment load command (segment_command_64).
#[derive(Debug, Clone)]
pub struct SegmentCommand {
    /// Segment name (max 16 chars, NUL-padded).
    pub segname: String,
    /// Virtual memory address where the segment begins.
    pub vmaddr: u64,
    /// Virtual memory size of the segment.
    pub vmsize: u64,
    /// File offset of the segment data.
    pub fileoff: u64,
    /// File size of the segment data.
    pub filesize: u64,
    /// Maximum permitted VM protections.
    pub maxprot: i32,
    /// Initial VM protections.
    pub initprot: i32,
    /// Number of sections within this segment.
    pub nsects: u32,
    /// Segment flags.
    pub flags: u32,
}

impl SegmentCommand {
    /// Check read permission.
    pub fn is_readable(&self) -> bool { (self.initprot & VM_PROT_READ) != 0 }

    /// Check write permission.
    pub fn is_writable(&self) -> bool { (self.initprot & VM_PROT_WRITE) != 0 }

    /// Check execute permission.
    pub fn is_executable(&self) -> bool { (self.initprot & VM_PROT_EXECUTE) != 0 }

    /// Check Apple-protected version flag.
    pub fn is_apple_protected(&self) -> bool {
        (self.flags & SG_PROTECTED_VERSION_1) != 0
    }

    /// Return the initprot as a human-readable string (e.g., "RWX").
    pub fn initprot_string(&self) -> String { vm_prot_string(self.initprot) }

    /// Return the maxprot as a human-readable string.
    pub fn maxprot_string(&self) -> String { vm_prot_string(self.maxprot) }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Section
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Section definition (section_64).
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (max 16 chars, NUL-padded).
    pub sectname: String,
    /// Containing segment name (max 16 chars, NUL-padded).
    pub segname: String,
    /// Virtual memory address of the section.
    pub addr: u64,
    /// Virtual memory size of the section.
    pub size: u64,
    /// File offset of the section data.
    pub offset: u32,
    /// Alignment (as power of 2).
    pub align: u32,
    /// File offset of relocation entries.
    pub reloff: u32,
    /// Number of relocation entries.
    pub nreloc: u32,
    /// Section flags (type in low byte, attributes in upper 3 bytes).
    pub flags: u32,
    /// Reserved field 1 (interpretation depends on section type).
    pub reserved1: u32,
    /// Reserved field 2 (interpretation depends on section type).
    pub reserved2: u32,
    /// Reserved field 3 (only present in section_64, zero in section).
    pub reserved3: u32,
}

impl Section {
    /// Return the section type (low 8 bits of flags).
    pub fn section_type(&self) -> u32 { self.flags & SECTION_TYPE_MASK }

    /// Return the section attributes (upper 24 bits of flags).
    pub fn attributes(&self) -> u32 { self.flags & SECTION_ATTRIBUTES_MASK }

    /// Return the human-readable section type name.
    pub fn type_name(&self) -> String { section_type_name(self.section_type()) }

    /// Return the human-readable attribute names.
    pub fn attribute_names(&self) -> Vec<&'static str> {
        section_attribute_names(self.flags)
    }

    /// True if this section contains pure instructions.
    pub fn is_pure_instructions(&self) -> bool {
        (self.flags & S_ATTR_PURE_INSTRUCTIONS) != 0
    }

    /// True if this section contains some instructions.
    pub fn is_some_instructions(&self) -> bool {
        (self.flags & S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    /// Heuristic: is this section executable?
    pub fn is_execute(&self) -> bool {
        if self.sectname == "__text" || self.segname == "__TEXT_EXEC" {
            return true;
        }
        self.is_pure_instructions() || self.is_some_instructions()
    }

    /// True if this is a zero-fill section.
    pub fn is_zerofill(&self) -> bool {
        let st = self.section_type();
        st == S_ZEROFILL || st == S_GB_ZEROFILL || st == S_THREAD_LOCAL_ZEROFILL
    }

    /// True if this section is of DEBUG type.
    pub fn is_debug(&self) -> bool {
        (self.flags & S_ATTR_DEBUG) != 0
    }

    /// True if this section contains code (heuristic).
    pub fn is_code(&self) -> bool {
        self.sectname == "__text"
            || self.sectname == "__stubs"
            || self.sectname == "__stub_helper"
            || self.is_pure_instructions()
    }

    /// True if this section contains data (heuristic).
    pub fn is_data(&self) -> bool {
        self.sectname == "__data"
            || self.sectname == "__const"
            || self.sectname == "__cstring"
            || self.sectname == "__cfstring"
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// NList
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A symbol table entry (nlist_64).
///
/// For 32-bit files the n_value field is zero-extended to u64.
#[derive(Debug, Clone)]
pub struct NList {
    /// Index into the string table for the symbol name.
    pub n_strx: u32,
    /// Symbol type flags (see N_* constants).
    pub n_type: u8,
    /// Section number where the symbol is defined, or NO_SECT.
    pub n_sect: u8,
    /// Symbol description (reference type, weak, etc.).
    pub n_desc: u16,
    /// Symbol value (virtual address for defined symbols).
    pub n_value: u64,
}

impl NList {
    /// True if the symbol is undefined.
    pub fn is_undefined(&self) -> bool {
        self.n_sect == NO_SECT && (self.n_type & N_TYPE) == N_UNDF
    }

    /// True if the symbol is absolute.
    pub fn is_absolute(&self) -> bool {
        self.n_sect == NO_SECT && (self.n_type & N_TYPE) == N_ABS
    }

    /// True if the symbol is defined in a section.
    pub fn is_section(&self) -> bool {
        (self.n_type & N_TYPE) == N_SECT
    }

    /// True if the symbol is indirect.
    pub fn is_indirect(&self) -> bool {
        self.n_sect == NO_SECT && (self.n_type & N_TYPE) == N_INDR
    }

    /// True if the symbol is prebound undefined.
    pub fn is_prebound_undefined(&self) -> bool {
        self.n_sect == NO_SECT && (self.n_type & N_TYPE) == N_PBUD
    }

    /// True if this is a debugger (STAB) symbol.
    pub fn is_stab(&self) -> bool { (self.n_type & N_STAB) != 0 }

    /// True if this is a private external symbol.
    pub fn is_private_external(&self) -> bool { (self.n_type & N_PEXT) != 0 }

    /// True if this is an external (global) symbol.
    pub fn is_external(&self) -> bool { (self.n_type & N_EXT) != 0 }

    /// Return the library ordinal (upper 8 bits of n_desc).
    pub fn library_ordinal(&self) -> u8 {
        ((self.n_desc >> 8) & 0xff) as u8
    }

    /// True if this is a lazy bind reference.
    pub fn is_lazy_bind(&self) -> bool {
        (self.n_desc & REFERENCE_TYPE) != 0
    }

    /// True if this is an ARM Thumb symbol.
    pub fn is_thumb(&self) -> bool {
        (self.n_desc & N_ARM_THUMB_DEF) != 0
    }

    /// True if the symbol has been discarded.
    pub fn is_discarded(&self) -> bool {
        (self.n_desc & N_DESC_DISCARDED) != 0
    }

    /// True if this is a weak reference.
    pub fn is_weak_ref(&self) -> bool {
        (self.n_desc & N_WEAK_REF) != 0
    }

    /// True if this is a weak definition.
    pub fn is_weak_def(&self) -> bool {
        (self.n_desc & N_WEAK_DEF) != 0
    }

    /// Entry size in bytes: 12 for 32-bit, 16 for 64-bit.
    pub fn entry_size(is_64bit: bool) -> usize {
        if is_64bit { 16 } else { 12 }
    }
}

/// Look up a symbol's string from the string table.
/// Returns "" if n_strx is 0 or out of bounds.
pub fn symbol_name<'a>(nlist: &NList, strings: &'a [u8]) -> &'a str {
    if nlist.n_strx == 0 { return ""; }
    let start = nlist.n_strx as usize;
    if start >= strings.len() { return ""; }
    let end = strings[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(strings.len());
    std::str::from_utf8(&strings[start..end]).unwrap_or("")
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Remaining Load Command Structs
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Symtab command (symbol table layout).
#[derive(Debug, Clone)]
pub struct SymtabCommand {
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

/// Dysymtab command (dynamic symbol table layout).
#[derive(Debug, Clone)]
pub struct DysymtabCommand {
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

/// Dylib command (dylib_command).
#[derive(Debug, Clone)]
pub struct DylibCommand {
    pub name: String,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

impl DylibCommand {
    /// Unpack a Mach-O packed version into a "M.m.p" string.
    pub fn version_string(version: u32) -> String {
        format!(
            "{}.{}.{}",
            version >> 16,
            (version >> 8) & 0xff,
            version & 0xff
        )
    }

    /// Current version as "M.m.p".
    pub fn current_version_str(&self) -> String {
        Self::version_string(self.current_version)
    }

    /// Compatibility version as "M.m.p".
    pub fn compat_version_str(&self) -> String {
        Self::version_string(self.compatibility_version)
    }
}

/// Dylinker command (dylinker_command).
#[derive(Debug, Clone)]
pub struct DylinkerCommand {
    pub name: String,
}

/// UUID command (uuid_command).
#[derive(Debug, Clone)]
pub struct UuidCommand {
    pub uuid: [u8; 16],
}

impl fmt::Display for UuidCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3],
            self.uuid[4], self.uuid[5], self.uuid[6], self.uuid[7],
            self.uuid[8], self.uuid[9], self.uuid[10], self.uuid[11],
            self.uuid[12], self.uuid[13], self.uuid[14], self.uuid[15],
        )
    }
}

/// Version minimum command (version_min_command).
#[derive(Debug, Clone)]
pub struct VersionMinCommand {
    pub version: u32,
    pub sdk: u32,
}

impl VersionMinCommand {
    pub fn version_string(&self) -> String {
        DylibCommand::version_string(self.version)
    }

    pub fn sdk_string(&self) -> String {
        DylibCommand::version_string(self.sdk)
    }
}

/// Source version command (source_version_command).
#[derive(Debug, Clone)]
pub struct SourceVersionCommand {
    /// Packed as A.B.C.D.E in 64 bits.
    pub version: u64,
}

impl SourceVersionCommand {
    pub fn version_parts(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.version >> 40,
            (self.version >> 30) & 0x3ff,
            (self.version >> 20) & 0x3ff,
            (self.version >> 10) & 0x3ff,
            self.version & 0x3ff,
        )
    }

    pub fn version_string(&self) -> String {
        let (a, b, c, d, e) = self.version_parts();
        format!("{}.{}.{}.{}.{}", a, b, c, d, e)
    }
}

/// Main command (LC_MAIN, entry_point_command).
#[derive(Debug, Clone)]
pub struct MainCommand {
    /// File offset of the entry point (__TEXT offset of main).
    pub entryoff: u64,
    /// Initial stack size (0 means use the default).
    pub stacksize: u64,
}

/// Rpath command (rpath_command).
#[derive(Debug, Clone)]
pub struct RpathCommand {
    pub path: String,
}

/// Linkedit data command (linkedit_data_command).
/// Used for LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO, LC_FUNCTION_STARTS,
/// LC_DATA_IN_CODE, LC_DYLD_EXPORTS_TRIE, LC_DYLD_CHAINED_FIXUPS.
#[derive(Debug, Clone)]
pub struct LinkeditDataCommand {
    pub dataoff: u32,
    pub datasize: u32,
}

/// DYLD info command (dyld_info_command).
#[derive(Debug, Clone)]
pub struct DyldInfoCommand {
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

/// Build version command (build_version_command).
#[derive(Debug, Clone)]
pub struct BuildVersionCommand {
    pub platform: u32,
    pub minos: u32,
    pub sdk: u32,
    pub ntools: u32,
    pub tools: Vec<BuildToolVersion>,
}

impl BuildVersionCommand {
    pub fn minos_string(&self) -> String { DylibCommand::version_string(self.minos) }
    pub fn sdk_string(&self) -> String { DylibCommand::version_string(self.sdk) }
    pub fn platform_name(&self) -> &'static str { platform_name(self.platform) }
}

/// A single tool version entry inside a build version command.
#[derive(Debug, Clone)]
pub struct BuildToolVersion {
    pub tool: u32,
    pub version: u32,
}

impl BuildToolVersion {
    pub fn tool_name(&self) -> &'static str { tool_name(self.tool) }
    pub fn version_string(&self) -> String { DylibCommand::version_string(self.version) }
}

/// DYLD environment command (LC_DYLD_ENVIRONMENT).
#[derive(Debug, Clone)]
pub struct DyldEnvironmentCommand {
    pub value: String,
}

/// Encryption info command (encryption_info_command / encryption_info_command_64).
#[derive(Debug, Clone)]
pub struct EncryptionInfoCommand {
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
    /// True if this was parsed from a 64-bit variant.
    pub is_64bit: bool,
}

/// Linker option command (LC_LINKER_OPTIONS).
#[derive(Debug, Clone)]
pub struct LinkerOptionCommand {
    pub count: u32,
    pub options: Vec<String>,
}

/// Fileset entry command (LC_FILESET_ENTRY).
#[derive(Debug, Clone)]
pub struct FilesetEntryCommand {
    pub vmaddr: u64,
    pub fileoff: u64,
    pub entry_id: String,
}

/// Note command (LC_NOTE).
#[derive(Debug, Clone)]
pub struct NoteCommand {
    pub data_owner: String,
    pub offset: u64,
    pub size: u64,
}

/// Relocation info (from section relocation entries).
#[derive(Debug, Clone)]
pub struct RelocationInfo {
    pub r_address: i32,
    pub r_symbolnum: u32,
    pub r_pcrel: bool,
    pub r_length: u8,
    pub r_extern: bool,
    pub r_type: u8,
    pub r_scattered: bool,
    pub r_value: i32,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Export Trie Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Parsed export trie.
#[derive(Debug, Clone)]
pub struct ExportTrie {
    pub entries: Vec<ExportEntry>,
}

/// A single export entry from the export trie.
#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub name: String,
    pub address: u64,
    pub flags: u64,
    pub other: u64,
    pub import_name: Option<String>,
}

impl ExportEntry {
    pub fn is_reexport(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0
    }

    pub fn is_weak(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION) != 0
    }

    pub fn is_stub_and_resolver(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0
    }

    pub fn kind(&self) -> u64 {
        self.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind() {
            EXPORT_SYMBOL_FLAGS_KIND_REGULAR => "REGULAR",
            EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => "THREAD_LOCAL",
            EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => "ABSOLUTE",
            _ => "UNKNOWN",
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Binding / Rebase Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindType {
    Pointer,
    TextAbsolute32,
    TextPcrel32,
}

impl BindType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            2 => BindType::TextAbsolute32,
            3 => BindType::TextPcrel32,
            _ => BindType::Pointer,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BindEntry {
    pub name: String,
    pub address: u64,
    pub bind_type: BindType,
    pub addend: i64,
    pub dylib_ordinal: i64,
    pub flags: u8,
}

#[derive(Debug, Clone)]
pub struct BindingInfo {
    pub entries: Vec<BindEntry>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Chained Fixups
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct ChainedFixups {
    pub starts_in_segment: Vec<u64>,
    pub imports: Vec<ChainedImport>,
    pub pointer_format: u16,
}

#[derive(Debug, Clone)]
pub struct ChainedImport {
    pub name: String,
    pub dylib_ordinal: i32,
    pub weak: bool,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Code Signature Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A parsed code signature superblob.
#[derive(Debug, Clone)]
pub struct CodeSignatureBlob {
    pub magic: u32,
    pub length: u32,
    pub count: u32,
    pub blobs: Vec<CodeSignatureIndex>,
}

/// Index entry inside a BlobWrapper.
#[derive(Debug, Clone)]
pub struct CodeSignatureIndex {
    pub blob_type: u32,
    pub offset: u32,
}

/// Parsed code signature requirements blob.
#[derive(Debug, Clone)]
pub struct CodeSignatureRequirement {
    pub kind: u32,
    pub data: Vec<u8>,
}

/// Parsed entitlements blob (raw XML plist data).
#[derive(Debug, Clone)]
pub struct CodeSignatureEntitlements {
    pub data: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// FAT / Universal Binary Parser
// ═══════════════════════════════════════════════════════════════════════════════════════════

const FAT_HEADER_SIZE: usize = 8;
const FAT_ARCH_SIZE: usize = 20; // 5 x u32

/// Parse a FAT (universal) binary.
///
/// On success returns `FatBinary`. Both big-endian (FAT_MAGIC) and
/// little-endian (FAT_CIGAM) variants are handled automatically.
///
/// # Errors
/// Returns `MachError::InvalidMagic` if the first four bytes are not a
/// FAT magic number, `MachError::TruncatedData` if the input is too
/// short, or `MachError::InvalidHeader` if the arch count is unreasonable.
pub fn parse_fat(data: &[u8]) -> MachResult<FatBinary> {
    if data.len() < FAT_HEADER_SIZE {
        return Err(MachError::TruncatedData);
    }

    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let num_arches = u32::from_be_bytes(data[4..8].try_into().unwrap());

    // Determine endianness: if magic reads as FAT_MAGIC in big-endian, it is BE;
    // otherwise try reading in little-endian to see if it matches FAT_CIGAM.
    fn read_magic(data: &[u8]) -> (u32, bool) {
        let be = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if be == FAT_MAGIC || is_fat_magic(be) {
            return (be, true);
        }
        let le = u32::from_le_bytes(data[0..4].try_into().unwrap());
        (le, false)
    }

    let (magic, is_be) = read_magic(data);
    if !is_fat_magic(magic) {
        return Err(MachError::InvalidMagic(magic));
    }

    // Re-read num_arches with correct endianness
    let num_arches = if is_be {
        u32::from_be_bytes(data[4..8].try_into().unwrap())
    } else {
        u32::from_le_bytes(data[4..8].try_into().unwrap())
    };

    if num_arches == 0 || num_arches > 256 {
        return Err(MachError::InvalidHeader);
    }

    let total_size = FAT_HEADER_SIZE + num_arches as usize * FAT_ARCH_SIZE;
    if data.len() < total_size {
        return Err(MachError::TruncatedData);
    }

    let mut arches = Vec::with_capacity(num_arches as usize);

    for i in 0..num_arches as usize {
        let off = FAT_HEADER_SIZE + i * FAT_ARCH_SIZE;
        let arch = if is_be {
            FatArch {
                cputype: i32::from_be_bytes(data[off..off + 4].try_into().unwrap()),
                cpusubtype: i32::from_be_bytes(data[off + 4..off + 8].try_into().unwrap()),
                offset: u32::from_be_bytes(data[off + 8..off + 12].try_into().unwrap()),
                size: u32::from_be_bytes(data[off + 12..off + 16].try_into().unwrap()),
                align: u32::from_be_bytes(data[off + 16..off + 20].try_into().unwrap()),
            }
        } else {
            FatArch {
                cputype: i32::from_le_bytes(data[off..off + 4].try_into().unwrap()),
                cpusubtype: i32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()),
                offset: u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()),
                size: u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap()),
                align: u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap()),
            }
        };
        arches.push(arch);
    }

    Ok(FatBinary { arches })
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Mach-O Parser
// ═══════════════════════════════════════════════════════════════════════════════════════════

const MAX_LOAD_COMMANDS: u32 = 32_768;
const SEGNAME_LEN: usize = 16;

/// Parse a complete Mach-O file.
///
/// Handles both 32-bit and 64-bit, big-endian and little-endian variants
/// by inspecting the magic number.
///
/// # Errors
/// Returns `MachError::InvalidMagic` if the magic is unrecognised,
/// `MachError::TruncatedData` if the data is shorter than expected,
/// or `MachError::TooManyCommands` if ncmds exceeds a sanity limit.
pub fn parse_macho(data: &[u8]) -> MachResult<MachOFile> {
    if data.len() < 28 {
        return Err(MachError::TruncatedData);
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());

    if !is_macho_magic(magic) {
        // Try big-endian
        let magic_be = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if is_macho_magic(magic_be) {
            return Err(MachError::InvalidMagic(magic_be));
        }
        return Err(MachError::InvalidMagic(magic));
    }

    let is_le = is_macho_le(magic);
    let is_64 = is_macho_64(magic);
    let header_size = if is_64 { 32 } else { 28 };

    if data.len() < header_size {
        return Err(MachError::TruncatedData);
    }

    // ── Helper closures ──
    let read_u32 = |off: usize| -> u32 {
        if is_le {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
        } else {
            u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
        }
    };

    let read_i32 = |off: usize| -> i32 {
        if is_le {
            i32::from_le_bytes(data[off..off + 4].try_into().unwrap())
        } else {
            i32::from_be_bytes(data[off..off + 4].try_into().unwrap())
        }
    };

    // ── Header ──
    let header = MachHeader {
        magic,
        cputype: read_i32(4),
        cpusubtype: read_i32(8),
        filetype: read_u32(12),
        ncmds: read_u32(16),
        sizeofcmds: read_u32(20),
        flags: read_u32(24),
        reserved: if is_64 { read_u32(28) } else { 0 },
    };

    if header.ncmds > MAX_LOAD_COMMANDS {
        return Err(MachError::TooManyCommands);
    }

    let cmd_start = header_size;
    let cmd_end = cmd_start + header.sizeofcmds as usize;
    if data.len() < cmd_end {
        return Err(MachError::TruncatedData);
    }

    // ── Parse load commands ──
    let mut commands: Vec<LoadCommand> = Vec::with_capacity(header.ncmds as usize);
    let mut sections: Vec<Section> = Vec::new();
    let mut symbols: Vec<NList> = Vec::new();
    let mut strings: Vec<u8> = Vec::new();

    let mut offset = cmd_start;
    for _ in 0..header.ncmds {
        if offset + 8 > data.len() {
            break;
        }

        let cmd = read_u32(offset);
        let cmdsize = read_u32(offset + 4) as usize;

        if cmdsize < 8 || offset + cmdsize > data.len() {
            break;
        }

        let cmd_data = &data[offset..offset + cmdsize];

        let lc = match cmd {
            LC_SEGMENT_64 => parse_segment_command_64(cmd_data, is_le, &mut sections),
            LC_SEGMENT => {
                // For completeness, we could parse 32-bit segments too.
                // Here we store them as Unknown for now.
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                    data: cmd_data.to_vec(),
                }
            }
            LC_SYMTAB => {
                parse_symtab_command(cmd_data, is_le, data, &mut symbols, &mut strings, is_64)
            }
            LC_DYSYMTAB => parse_dysymtab_command(cmd_data, is_le),
            LC_UUID => parse_uuid_command(cmd_data),
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => parse_dyld_info_command(cmd_data, is_le),
            LC_BUILD_VERSION => parse_build_version_command(cmd_data, is_le),
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS => parse_version_min_command(cmd_data, is_le),
            LC_SOURCE_VERSION => parse_source_version_command(cmd_data, is_le),
            LC_MAIN => parse_main_command(cmd_data, is_le),
            LC_DYLD_ENVIRONMENT => parse_dyld_environment_command(cmd_data),
            LC_LOAD_DYLIB => parse_dylib_command(cmd_data, is_le, LoadCommand::LoadDylib),
            LC_ID_DYLIB => parse_dylib_command(cmd_data, is_le, LoadCommand::IdDylib),
            LC_LOAD_WEAK_DYLIB => parse_dylib_command(cmd_data, is_le, LoadCommand::LoadWeakDylib),
            LC_REEXPORT_DYLIB => parse_dylib_command(cmd_data, is_le, LoadCommand::ReexportDylib),
            LC_LOAD_DYLINKER | LC_ID_DYLINKER => parse_dylinker_command(cmd_data, is_le),
            LC_RPATH => parse_rpath_command(cmd_data, is_le),
            LC_CODE_SIGNATURE => {
                parse_linkedit_data_command(cmd_data, is_le, LoadCommand::CodeSignature)
            }
            LC_SEGMENT_SPLIT_INFO => {
                parse_linkedit_data_command(cmd_data, is_le, LoadCommand::SegmentSplitInfo)
            }
            LC_FUNCTION_STARTS => {
                parse_linkedit_data_command(cmd_data, is_le, LoadCommand::FunctionStarts)
            }
            LC_DATA_IN_CODE => {
                parse_linkedit_data_command(cmd_data, is_le, LoadCommand::DataInCode)
            }
            LC_DYLD_EXPORTS_TRIE => {
                parse_linkedit_data_command(cmd_data, is_le, LoadCommand::DyldExportsTrie)
            }
            LC_DYLD_CHAINED_FIXUPS => {
                parse_linkedit_data_command(cmd_data, is_le, LoadCommand::DyldChainedFixups)
            }
            LC_ENCRYPTION_INFO => parse_encryption_info_command(cmd_data, is_le, false),
            LC_ENCRYPTION_INFO_64 => parse_encryption_info_command(cmd_data, is_le, true),
            LC_LINKER_OPTIONS => parse_linker_option_command(cmd_data, is_le),
            LC_FILESET_ENTRY => parse_fileset_entry_command(cmd_data, is_le),
            LC_NOTE => parse_note_command(cmd_data, is_le),
            _ => LoadCommand::Unknown {
                cmd,
                cmdsize: cmdsize as u32,
                data: cmd_data.to_vec(),
            },
        };

        commands.push(lc);
        offset += cmdsize;
    }

    Ok(MachOFile {
        header,
        commands,
        sections,
        symbols,
        strings,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Low-level read helpers
// ═══════════════════════════════════════════════════════════════════════════════════════════

fn read_le_u32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(d[off..off + 4].try_into().unwrap())
}
fn read_be_u32(d: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(d[off..off + 4].try_into().unwrap())
}
fn read_le_u64(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}
fn read_be_u64(d: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(d[off..off + 8].try_into().unwrap())
}
fn read_le_i32(d: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(d[off..off + 4].try_into().unwrap())
}
fn read_be_i32(d: &[u8], off: usize) -> i32 {
    i32::from_be_bytes(d[off..off + 4].try_into().unwrap())
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Individual Load Command Parsers
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Parse LC_SEGMENT_64 (segment_command_64).
///
/// The segment's sections are appended to the caller-supplied `sections` vector.
fn parse_segment_command_64(data: &[u8], is_le: bool, sections: &mut Vec<Section>) -> LoadCommand {
    let segname = read_padded_string(&data[8..24], SEGNAME_LEN);

    let (vmaddr, vmsize, fileoff, filesize) = if is_le {
        (
            read_le_u64(data, 24),
            read_le_u64(data, 32),
            read_le_u64(data, 40),
            read_le_u64(data, 48),
        )
    } else {
        (
            read_be_u64(data, 24),
            read_be_u64(data, 32),
            read_be_u64(data, 40),
            read_be_u64(data, 48),
        )
    };

    let maxprot = if is_le { read_le_i32(data, 56) } else { read_be_i32(data, 56) };
    let initprot = if is_le { read_le_i32(data, 60) } else { read_be_i32(data, 60) };
    let nsects = if is_le { read_le_u32(data, 64) } else { read_be_u32(data, 64) };
    let flags = if is_le { read_le_u32(data, 68) } else { read_be_u32(data, 68) };

    let section_size: usize = 80; // section_64 = 80 bytes
    let sect_start: usize = 72;

    for i in 0..nsects as usize {
        let off = sect_start + i * section_size;
        if off + section_size > data.len() {
            break;
        }
        let sectname = read_padded_string(&data[off..off + 16], SEGNAME_LEN);
        let sect_segname = read_padded_string(&data[off + 16..off + 32], SEGNAME_LEN);

        let (addr, size) = if is_le {
            (read_le_u64(data, off + 32), read_le_u64(data, off + 40))
        } else {
            (read_be_u64(data, off + 32), read_be_u64(data, off + 40))
        };

        let sect_offset = if is_le { read_le_u32(data, off + 48) } else { read_be_u32(data, off + 48) };
        let align = if is_le { read_le_u32(data, off + 52) } else { read_be_u32(data, off + 52) };
        let reloff = if is_le { read_le_u32(data, off + 56) } else { read_be_u32(data, off + 56) };
        let nreloc = if is_le { read_le_u32(data, off + 60) } else { read_be_u32(data, off + 60) };
        let sect_flags = if is_le { read_le_u32(data, off + 64) } else { read_be_u32(data, off + 64) };
        let reserved1 = if is_le { read_le_u32(data, off + 68) } else { read_be_u32(data, off + 68) };
        let reserved2 = if is_le { read_le_u32(data, off + 72) } else { read_be_u32(data, off + 72) };
        let reserved3 = if is_le { read_le_u32(data, off + 76) } else { read_be_u32(data, off + 76) };

        sections.push(Section {
            sectname,
            segname: sect_segname,
            addr,
            size,
            offset: sect_offset,
            align,
            reloff,
            nreloc,
            flags: sect_flags,
            reserved1,
            reserved2,
            reserved3,
        });
    }

    LoadCommand::Segment64(SegmentCommand {
        segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot,
        initprot,
        nsects,
        flags,
    })
}

/// Parse LC_SYMTAB: reads symbol table and string table from the full file data.
fn parse_symtab_command(
    cmd_data: &[u8],
    is_le: bool,
    full_data: &[u8],
    symbols: &mut Vec<NList>,
    strings: &mut Vec<u8>,
    is_64: bool,
) -> LoadCommand {
    let symoff = if is_le { read_le_u32(cmd_data, 8) } else { read_be_u32(cmd_data, 8) };
    let nsyms = if is_le { read_le_u32(cmd_data, 12) } else { read_be_u32(cmd_data, 12) };
    let stroff = if is_le { read_le_u32(cmd_data, 16) } else { read_be_u32(cmd_data, 16) };
    let strsize = if is_le { read_le_u32(cmd_data, 20) } else { read_be_u32(cmd_data, 20) };

    // Read string table
    let str_start = stroff as usize;
    let str_end = str_start + strsize as usize;
    if str_end <= full_data.len() {
        *strings = full_data[str_start..str_end].to_vec();
    }

    // Read symbols
    let nlist_size = if is_64 { 16 } else { 12 };
    let sym_start = symoff as usize;
    let sym_end = sym_start + nsyms as usize * nlist_size;
    if sym_end <= full_data.len() {
        for i in 0..nsyms as usize {
            let off = sym_start + i * nlist_size;
            let n_strx = if is_le {
                read_le_u32(full_data, off)
            } else {
                read_be_u32(full_data, off)
            };
            let n_type = full_data[off + 4];
            let n_sect = full_data[off + 5];
            let n_desc = if is_le {
                u16::from_le_bytes(full_data[off + 6..off + 8].try_into().unwrap())
            } else {
                u16::from_be_bytes(full_data[off + 6..off + 8].try_into().unwrap())
            };
            let n_value = if is_64 {
                if is_le {
                    read_le_u64(full_data, off + 8)
                } else {
                    read_be_u64(full_data, off + 8)
                }
            } else {
                if is_le {
                    read_le_u32(full_data, off + 8) as u64
                } else {
                    read_be_u32(full_data, off + 8) as u64
                }
            };

            symbols.push(NList {
                n_strx,
                n_type,
                n_sect,
                n_desc,
                n_value,
            });
        }
    }

    LoadCommand::Symtab(SymtabCommand {
        symoff,
        nsyms,
        stroff,
        strsize,
    })
}

/// Parse LC_DYSYMTAB.
fn parse_dysymtab_command(data: &[u8], is_le: bool) -> LoadCommand {
    let read_u = |off: usize| -> u32 {
        if is_le {
            read_le_u32(data, off)
        } else {
            read_be_u32(data, off)
        }
    };
    LoadCommand::Dysymtab(DysymtabCommand {
        ilocalsym: read_u(8), nlocalsym: read_u(12),
        iextdefsym: read_u(16), nextdefsym: read_u(20),
        iundefsym: read_u(24), nundefsym: read_u(28),
        tocoff: read_u(32), ntoc: read_u(36),
        modtaboff: read_u(40), nmodtab: read_u(44),
        extrefsymoff: read_u(48), nextrefsyms: read_u(52),
        indirectsymoff: read_u(56), nindirectsyms: read_u(60),
        extreloff: read_u(64), nextrel: read_u(68),
        locreloff: read_u(72), nlocrel: read_u(76),
    })
}

/// Parse LC_DYLD_INFO / LC_DYLD_INFO_ONLY.
fn parse_dyld_info_command(data: &[u8], is_le: bool) -> LoadCommand {
    let read_u = |off: usize| -> u32 {
        if is_le { read_le_u32(data, off) } else { read_be_u32(data, off) }
    };
    LoadCommand::DyldInfo(DyldInfoCommand {
        rebase_off: read_u(8), rebase_size: read_u(12),
        bind_off: read_u(16), bind_size: read_u(20),
        weak_bind_off: read_u(24), weak_bind_size: read_u(28),
        lazy_bind_off: read_u(32), lazy_bind_size: read_u(36),
        export_off: read_u(40), export_size: read_u(44),
    })
}

/// Parse LC_UUID.
fn parse_uuid_command(data: &[u8]) -> LoadCommand {
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&data[8..24]);
    LoadCommand::Uuid(UuidCommand { uuid })
}

/// Parse LC_BUILD_VERSION.
fn parse_build_version_command(data: &[u8], is_le: bool) -> LoadCommand {
    let platform = if is_le { read_le_u32(data, 8) } else { read_be_u32(data, 8) };
    let minos = if is_le { read_le_u32(data, 12) } else { read_be_u32(data, 12) };
    let sdk = if is_le { read_le_u32(data, 16) } else { read_be_u32(data, 16) };
    let ntools = if is_le { read_le_u32(data, 20) } else { read_be_u32(data, 20) };

    let mut tools = Vec::new();
    for i in 0..ntools as usize {
        let off = 24 + i * 8;
        if off + 8 > data.len() { break; }
        let tool = if is_le { read_le_u32(data, off) } else { read_be_u32(data, off) };
        let version = if is_le { read_le_u32(data, off + 4) } else { read_be_u32(data, off + 4) };
        tools.push(BuildToolVersion { tool, version });
    }

    LoadCommand::BuildVersion(BuildVersionCommand {
        platform, minos, sdk, ntools, tools,
    })
}

/// Parse LC_VERSION_MIN_*.
fn parse_version_min_command(data: &[u8], is_le: bool) -> LoadCommand {
    let version = if is_le { read_le_u32(data, 8) } else { read_be_u32(data, 8) };
    let sdk = if is_le { read_le_u32(data, 12) } else { read_be_u32(data, 12) };
    LoadCommand::VersionMin(VersionMinCommand { version, sdk })
}

/// Parse LC_SOURCE_VERSION.
fn parse_source_version_command(data: &[u8], is_le: bool) -> LoadCommand {
    let version = if is_le { read_le_u64(data, 8) } else { read_be_u64(data, 8) };
    LoadCommand::SourceVersion(SourceVersionCommand { version })
}

/// Parse LC_MAIN.
fn parse_main_command(data: &[u8], is_le: bool) -> LoadCommand {
    let entryoff = if is_le { read_le_u64(data, 8) } else { read_be_u64(data, 8) };
    let stacksize = if is_le { read_le_u64(data, 16) } else { read_be_u64(data, 16) };
    LoadCommand::Main(MainCommand { entryoff, stacksize })
}

/// Parse LC_DYLD_ENVIRONMENT.
fn parse_dyld_environment_command(data: &[u8]) -> LoadCommand {
    let value = read_padded_string(&data[8..], data.len() - 8);
    LoadCommand::DyldEnvironment(DyldEnvironmentCommand { value })
}

/// Parse LC_LOAD_DYLIB / LC_ID_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB.
fn parse_dylib_command(
    data: &[u8],
    is_le: bool,
    mk: fn(DylibCommand) -> LoadCommand,
) -> LoadCommand {
    // dylib_command layout:
    //   cmd(4) + cmdsize(4) + name_offset(4) + timestamp(4) +
    //   current_version(4) + compatibility_version(4)
    let name_offset = if is_le { read_le_u32(data, 8) } else { read_be_u32(data, 8) };
    let timestamp = if is_le { read_le_u32(data, 12) } else { read_be_u32(data, 12) };
    let current_version = if is_le { read_le_u32(data, 16) } else { read_be_u32(data, 16) };
    let compatibility_version = if is_le { read_le_u32(data, 20) } else { read_be_u32(data, 20) };

    let name_start = name_offset as usize;
    let name = if name_start < data.len() {
        read_padded_string(&data[name_start..], data.len() - name_start)
    } else {
        String::new()
    };

    mk(DylibCommand {
        name,
        timestamp,
        current_version,
        compatibility_version,
    })
}

/// Parse LC_LOAD_DYLINKER / LC_ID_DYLINKER.
fn parse_dylinker_command(data: &[u8], is_le: bool) -> LoadCommand {
    let name_offset = if is_le { read_le_u32(data, 8) } else { read_be_u32(data, 8) };
    let name_start = name_offset as usize;
    let name = if name_start < data.len() {
        read_padded_string(&data[name_start..], data.len() - name_start)
    } else {
        String::new()
    };
    LoadCommand::Dylinker(DylinkerCommand { name })
}

/// Parse LC_RPATH.
fn parse_rpath_command(data: &[u8], is_le: bool) -> LoadCommand {
    let path_offset = if is_le { read_le_u32(data, 8) } else { read_be_u32(data, 8) };
    let path_start = path_offset as usize;
    let path = if path_start < data.len() {
        read_padded_string(&data[path_start..], data.len() - path_start)
    } else {
        String::new()
    };
    LoadCommand::Rpath(RpathCommand { path })
}

/// Parse linkedit_data_command (used for multiple LC_* commands).
fn parse_linkedit_data_command(
    data: &[u8],
    is_le: bool,
    mk: fn(LinkeditDataCommand) -> LoadCommand,
) -> LoadCommand {
    let dataoff = if is_le { read_le_u32(data, 8) } else { read_be_u32(data, 8) };
    let datasize = if is_le { read_le_u32(data, 12) } else { read_be_u32(data, 12) };
    mk(LinkeditDataCommand { dataoff, datasize })
}

/// Parse LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64.
fn parse_encryption_info_command(data: &[u8], is_le: bool, is_64bit: bool) -> LoadCommand {
    let cryptoff = if is_le { read_le_u32(data, 8) } else { read_be_u32(data, 8) };
    let cryptsize = if is_le { read_le_u32(data, 12) } else { read_be_u32(data, 12) };
    let cryptid = if is_le { read_le_u32(data, 16) } else { read_be_u32(data, 16) };

    let lc = EncryptionInfoCommand {
        cryptoff,
        cryptsize,
        cryptid,
        is_64bit,
    };
    if is_64bit {
        LoadCommand::EncryptionInfo64(lc)
    } else {
        LoadCommand::EncryptionInfo(lc)
    }
}

/// Parse LC_LINKER_OPTIONS.
fn parse_linker_option_command(data: &[u8], is_le: bool) -> LoadCommand {
    let count = if is_le { read_le_u32(data, 8) } else { read_be_u32(data, 8) };
    let mut options = Vec::new();
    let strings_data = &data[12..];
    let mut pos = 0usize;
    for _ in 0..count as usize {
        if pos >= strings_data.len() { break; }
        let end = strings_data[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| pos + p)
            .unwrap_or(strings_data.len());
        let opt = String::from_utf8_lossy(&strings_data[pos..end]).to_string();
        if !opt.is_empty() {
            options.push(opt);
        }
        pos = end + 1;
    }
    LoadCommand::LinkerOption(LinkerOptionCommand { count, options })
}

/// Parse LC_FILESET_ENTRY.
fn parse_fileset_entry_command(data: &[u8], is_le: bool) -> LoadCommand {
    let vmaddr = if is_le { read_le_u64(data, 8) } else { read_be_u64(data, 8) };
    let fileoff = if is_le { read_le_u64(data, 16) } else { read_be_u64(data, 16) };
    let entry_id_offset = if is_le { read_le_u32(data, 24) } else { read_be_u32(data, 24) };
    let entry_start = entry_id_offset as usize;
    let entry_id = if entry_start < data.len() {
        read_padded_string(&data[entry_start..], data.len() - entry_start)
    } else {
        String::new()
    };
    LoadCommand::FilesetEntry(FilesetEntryCommand { vmaddr, fileoff, entry_id })
}

/// Parse LC_NOTE.
fn parse_note_command(data: &[u8], is_le: bool) -> LoadCommand {
    let data_owner = read_padded_string(&data[8..24], SEGNAME_LEN);
    let offset = if is_le { read_le_u64(data, 24) } else { read_be_u64(data, 24) };
    let size = if is_le { read_le_u64(data, 32) } else { read_be_u64(data, 32) };
    LoadCommand::Note(NoteCommand { data_owner, offset, size })
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Export Trie Parser
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Parse the export trie from raw bytes.
///
/// `data` should point to the start of the export trie within the file.
///
/// The export trie is a prefix tree (trie) where internal nodes carry
/// string edges leading to child nodes, and terminal nodes carry flags,
/// an address (or import name for re-exports), and optionally a resolver
/// address for stub-and-resolver symbols.
pub fn parse_export_trie(data: &[u8]) -> MachResult<ExportTrie> {
    if data.is_empty() {
        return Ok(ExportTrie { entries: vec![] });
    }

    let mut entries = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();

    fn parse_node(
        data: &[u8],
        base: usize,
        prefix: &str,
        node_offset: u32,
        entries: &mut Vec<ExportEntry>,
        visited: &mut HashSet<u32>,
    ) -> MachResult<()> {
        if !visited.insert(node_offset) {
            return Err(MachError::CircularExportTrie);
        }

        let off = base + node_offset as usize;
        if off >= data.len() {
            return Err(MachError::InvalidExportTrie);
        }

        let (terminal_size, tsz_len) = decode_uleb128(&data[off..])?;
        let mut pos = off + tsz_len;

        if terminal_size > 0 {
            // Terminal node: read flags, address, resolver info
            if pos >= data.len() {
                return Err(MachError::InvalidExportTrie);
            }
            let (flags, flags_len) = decode_uleb128(&data[pos..])?;
            pos += flags_len;

            let (address, other, import_name) = if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0 {
                let (other_val, o_len) = decode_uleb128(&data[pos..])?;
                pos += o_len;
                let name_end = data[pos..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(data.len() - pos);
                let imp_name = String::from_utf8_lossy(&data[pos..pos + name_end]).to_string();
                pos += name_end + 1;
                (0, other_val, Some(imp_name))
            } else {
                let (addr_val, a_len) = decode_uleb128(&data[pos..])?;
                pos += a_len;
                let mut other_val = 0u64;
                if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0 {
                    let (o_val, o_len) = decode_uleb128(&data[pos..])?;
                    pos += o_len;
                    other_val = o_val;
                }
                (addr_val, other_val, None)
            };

            entries.push(ExportEntry {
                name: prefix.to_string(),
                address,
                flags,
                other,
                import_name,
            });
        }

        // Children follow after terminal information. `pos` already = where children begin
        // when terminal_size > 0. Otherwise start from off + tsz_len.
        let children_pos = if terminal_size > 0 {
            pos
        } else {
            off + tsz_len
        };
        if children_pos >= data.len() {
            return Ok(());
        }

        let (num_children, nc_len) = decode_uleb128(&data[children_pos..])?;
        let mut child_pos = children_pos + nc_len;

        for _ in 0..num_children {
            if child_pos >= data.len() { break; }
            // Read child edge label (NUL-terminated string)
            let label_end = data[child_pos..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.len() - child_pos);
            let child_label =
                String::from_utf8_lossy(&data[child_pos..child_pos + label_end]).to_string();
            child_pos += label_end + 1;

            if child_pos >= data.len() { break; }
            let (child_offset, co_len) = decode_uleb128(&data[child_pos..])?;
            child_pos += co_len;

            let child_prefix = if prefix.is_empty() {
                child_label
            } else {
                format!("{}{}", prefix, child_label)
            };

            parse_node(
                data,
                base,
                &child_prefix,
                child_offset as u32,
                entries,
                visited,
            )?;
        }

        Ok(())
    }

    parse_node(data, 0, "", 0, &mut entries, &mut visited)?;

    // Sort entries by name for deterministic output
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ExportTrie { entries })
}

/// Convenience: extract and parse the export trie from a fully parsed MachOFile.
pub fn parse_macho_export_trie(file_data: &[u8], macho: &MachOFile) -> MachResult<ExportTrie> {
    // Try DYLD_INFO first
    if let Some(dyld_info) = macho.dyld_info() {
        if dyld_info.export_off > 0 && dyld_info.export_size > 0 {
            let start = dyld_info.export_off as usize;
            let end = start + dyld_info.export_size as usize;
            if end <= file_data.len() {
                return parse_export_trie(&file_data[start..end]);
            }
        }
    }
    // Fallback: LC_DYLD_EXPORTS_TRIE
    if let Some(lc) = macho.dyld_exports_trie() {
        if lc.dataoff > 0 && lc.datasize > 0 {
            let start = lc.dataoff as usize;
            let end = start + lc.datasize as usize;
            if end <= file_data.len() {
                return parse_export_trie(&file_data[start..end]);
            }
        }
    }
    Ok(ExportTrie { entries: vec![] })
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// DYLD Opcode-Based Binding Parser
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Parse DYLD binding opcodes from compressed bind data.
///
/// `data` should be the raw binding opcode stream.
/// `segment_base_addresses` are the vmaddr values of each segment in order
/// (segment index 0 = segments[0].vmaddr, etc.), used to compute absolute
/// addresses from segment-relative offsets.
/// `is_lazy` should be true for lazy binding streams.
pub fn parse_binding_info(
    data: &[u8],
    segment_base_addresses: &[u64],
    is_lazy: bool,
) -> MachResult<BindingInfo> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    let mut seg_index: u8 = 0;
    let mut seg_offset: u64 = 0;
    let mut bind_type: BindType = BindType::Pointer;
    let mut dylib_ordinal: i64 = 0;
    let mut symbol_name = String::new();
    let mut symbol_flags: u8 = 0;
    let mut addend: i64 = 0;
    let mut count: u64 = 0;

    let pointer_size: u64 = 8; // Default to 64-bit

    /// Compute absolute address: segment base + offset.
    fn compute_addr(seg_index: u8, seg_offset: u64, bases: &[u64]) -> u64 {
        if (seg_index as usize) < bases.len() {
            bases[seg_index as usize] + seg_offset
        } else {
            seg_offset
        }
    }

    /// Flush accumulated entries.
    fn flush(
        entries: &mut Vec<BindEntry>,
        name: &str,
        bases: &[u64],
        seg_index: u8,
        seg_offset: u64,
        count: u64,
        offset_per_entry: u64,
        bind_type: BindType,
        addend: i64,
        dylib_ordinal: i64,
        symbol_flags: u8,
    ) {
        if name.is_empty() || count == 0 {
            return;
        }
        for i in 0..count {
            let addr = compute_addr(seg_index, seg_offset + i * offset_per_entry, bases);
            entries.push(BindEntry {
                name: name.to_string(),
                address: addr,
                bind_type,
                addend,
                dylib_ordinal,
                flags: symbol_flags,
            });
        }
    }

    while pos < data.len() {
        let byte = data[pos];
        pos += 1;
        let opcode = byte & BIND_OPCODE_MASK;
        let imm = byte & BIND_IMMEDIATE_MASK;

        match opcode {
            BIND_OPCODE_DONE => {
                flush(
                    &mut entries, &symbol_name, segment_base_addresses,
                    seg_index, seg_offset, count, pointer_size,
                    bind_type, addend, dylib_ordinal, symbol_flags,
                );
                if !is_lazy {
                    return Ok(BindingInfo { entries });
                }
                // Reset state for next dylib in lazy bind
                seg_index = 0;
                seg_offset = 0;
                bind_type = BindType::Pointer;
                dylib_ordinal = 0;
                symbol_name.clear();
                symbol_flags = 0;
                addend = 0;
                count = 0;
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                dylib_ordinal = imm as i64;
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                let (val, len) = decode_uleb128(&data[pos..])?;
                pos += len;
                dylib_ordinal = val as i64;
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                if imm == 0 {
                    dylib_ordinal = 0;
                } else {
                    dylib_ordinal = (imm as i32 | 0xFFFF_FFF0u32 as i32) as i64;
                }
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                // Flush previous symbol's entries
                flush(
                    &mut entries, &symbol_name, segment_base_addresses,
                    seg_index, seg_offset, count, pointer_size,
                    bind_type, addend, dylib_ordinal, symbol_flags,
                );
                count = 0;
                symbol_flags = imm;
                let name_end = data[pos..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(data.len() - pos);
                symbol_name =
                    String::from_utf8_lossy(&data[pos..pos + name_end]).to_string();
                pos += name_end + 1;
            }
            BIND_OPCODE_SET_TYPE_IMM => {
                bind_type = BindType::from_u8(imm);
            }
            BIND_OPCODE_SET_ADDEND_SLEB => {
                let (val, len) = decode_sleb128(&data[pos..])?;
                pos += len;
                addend = val;
            }
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_index = imm;
                let (val, len) = decode_uleb128(&data[pos..])?;
                pos += len;
                seg_offset = val;
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                let (val, len) = decode_uleb128(&data[pos..])?;
                pos += len;
                seg_offset += val;
            }
            BIND_OPCODE_DO_BIND => {
                flush(
                    &mut entries, &symbol_name, segment_base_addresses,
                    seg_index, seg_offset, 1, 0,
                    bind_type, addend, dylib_ordinal, symbol_flags,
                );
                seg_offset += pointer_size;
                count = 0;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                flush(
                    &mut entries, &symbol_name, segment_base_addresses,
                    seg_index, seg_offset, 1, 0,
                    bind_type, addend, dylib_ordinal, symbol_flags,
                );
                let (val, len) = decode_uleb128(&data[pos..])?;
                pos += len;
                seg_offset += val + pointer_size;
                count = 0;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                flush(
                    &mut entries, &symbol_name, segment_base_addresses,
                    seg_index, seg_offset, 1, 0,
                    bind_type, addend, dylib_ordinal, symbol_flags,
                );
                seg_offset += (imm as u64) * pointer_size + pointer_size;
                count = 0;
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (cnt, cnt_len) = decode_uleb128(&data[pos..])?;
                pos += cnt_len;
                let (skp, skp_len) = decode_uleb128(&data[pos..])?;
                pos += skp_len;

                if !symbol_name.is_empty() {
                    for i in 0..cnt {
                        let addr = compute_addr(
                            seg_index,
                            seg_offset + i * (pointer_size + skp),
                            segment_base_addresses,
                        );
                        entries.push(BindEntry {
                            name: symbol_name.clone(),
                            address: addr,
                            bind_type,
                            addend,
                            dylib_ordinal,
                            flags: symbol_flags,
                        });
                    }
                }
                seg_offset += cnt * (pointer_size + skp);
                count = 0;
            }
            BIND_OPCODE_THREADED => {
                let sub = imm;
                match sub {
                    BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB => {
                        let (_val, len) = decode_uleb128(&data[pos..])?;
                        pos += len;
                    }
                    BIND_SUBOPCODE_THREADED_APPLY => {
                        if !symbol_name.is_empty() {
                            let addr = compute_addr(seg_index, seg_offset, segment_base_addresses);
                            entries.push(BindEntry {
                                name: symbol_name.clone(),
                                address: addr,
                                bind_type,
                                addend,
                                dylib_ordinal,
                                flags: symbol_flags,
                            });
                        }
                        seg_offset += pointer_size;
                    }
                    _ => {}
                }
            }
            _ => {
                // Unknown opcode; skip
            }
        }
    }

    Ok(BindingInfo { entries })
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Code Signature Blob Parser
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Parse a code signature superblob (CSMAGIC_BLOBWRAPPER).
///
/// The superblob contains a magic, length, count, followed by `count`
/// index entries and their referenced data blobs.
/// Returns `CodeSignatureBlob` or `MachError::InvalidCodeSignature`.
pub fn parse_code_signature(data: &[u8]) -> MachResult<CodeSignatureBlob> {
    if data.len() < 8 {
        return Err(MachError::InvalidCodeSignature);
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let length = u32::from_be_bytes(data[4..8].try_into().unwrap());

    if magic != CSMAGIC_BLOBWRAPPER && magic != CSMAGIC_EMBEDDED_SIGNATURE
        && magic != CSMAGIC_DETACHED_SIGNATURE
    {
        return Err(MachError::InvalidCodeSignature);
    }

    if length as usize > data.len() || length < 12 {
        return Err(MachError::InvalidCodeSignature);
    }

    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let mut blobs = Vec::new();

    for i in 0..count as usize {
        let off = 12 + i * 8;
        if off + 8 > length as usize {
            break;
        }
        let blob_type = u32::from_be_bytes(data[off..off + 4].try_into().unwrap());
        let blob_offset = u32::from_be_bytes(data[off + 4..off + 8].try_into().unwrap());
        blobs.push(CodeSignatureIndex {
            blob_type,
            offset: blob_offset,
        });
    }

    Ok(CodeSignatureBlob {
        magic,
        length,
        count,
        blobs,
    })
}

/// Extract the entitlements XML data from a code signature superblob.
///
/// Searches for a CSMAGIC_ENTITLEMENTS blob index and returns the
/// corresponding data. Note: the actual XML string may be compressed.
pub fn parse_entitlements(superblob: &[u8]) -> MachResult<CodeSignatureEntitlements> {
    let cs = parse_code_signature(superblob)?;
    for idx in &cs.blobs {
        if idx.blob_type == CSMAGIC_ENTITLEMENTS {
            let blob_start = idx.offset as usize;
            // The entitlements blob itself has an 8-byte header (magic + length)
            if blob_start + 8 > superblob.len() {
                continue;
            }
            let blob_magic =
                u32::from_be_bytes(superblob[blob_start..blob_start + 4].try_into().unwrap());
            let blob_len =
                u32::from_be_bytes(superblob[blob_start + 4..blob_start + 8].try_into().unwrap());
            if blob_magic == CSMAGIC_ENTITLEMENTS
                && blob_start + blob_len as usize <= superblob.len()
                && blob_len > 8
            {
                return Ok(CodeSignatureEntitlements {
                    data: superblob[blob_start + 8..blob_start + blob_len as usize].to_vec(),
                });
            }
        }
    }
    Err(MachError::InvalidCodeSignature)
}

/// Extract requirement blobs from a code signature superblob.
pub fn parse_requirements(superblob: &[u8]) -> MachResult<Vec<CodeSignatureRequirement>> {
    let cs = parse_code_signature(superblob)?;
    let mut reqs = Vec::new();
    for idx in &cs.blobs {
        if idx.blob_type == CSMAGIC_REQUIREMENT || idx.blob_type == CSMAGIC_REQUIREMENTS {
            let blob_start = idx.offset as usize;
            if blob_start + 12 > superblob.len() {
                continue;
            }
            let blob_magic =
                u32::from_be_bytes(superblob[blob_start..blob_start + 4].try_into().unwrap());
            let blob_len =
                u32::from_be_bytes(superblob[blob_start + 4..blob_start + 8].try_into().unwrap());
            let kind =
                u32::from_be_bytes(superblob[blob_start + 8..blob_start + 12].try_into().unwrap());

            if blob_start + blob_len as usize <= superblob.len() && blob_len > 12 {
                reqs.push(CodeSignatureRequirement {
                    kind,
                    data: superblob[blob_start + 12..blob_start + blob_len as usize].to_vec(),
                });
            }
        }
    }
    Ok(reqs)
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Magic Constants ────────────────────────────────────────────────────

    #[test]
    fn test_magic_constants() {
        assert!(is_macho_magic(MH_MAGIC_64));
        assert!(is_macho_magic(MH_CIGAM_64));
        assert!(is_macho_magic(MH_MAGIC));
        assert!(is_macho_magic(MH_CIGAM));
        assert!(!is_macho_magic(0xdeadbeef));
        assert!(!is_macho_magic(FAT_MAGIC));

        assert!(is_macho_64(MH_MAGIC_64));
        assert!(is_macho_64(MH_CIGAM_64));
        assert!(!is_macho_64(MH_MAGIC));
        assert!(!is_macho_64(MH_CIGAM));

        assert!(is_macho_le(MH_CIGAM));
        assert!(is_macho_le(MH_CIGAM_64));
        assert!(!is_macho_le(MH_MAGIC));
        assert!(!is_macho_le(MH_MAGIC_64));

        assert!(is_fat_magic(FAT_MAGIC));
        assert!(is_fat_magic(FAT_CIGAM));
        assert!(!is_fat_magic(MH_MAGIC));
    }

    // ── CPU Type Constants ─────────────────────────────────────────────────

    #[test]
    fn test_cpu_type_constants() {
        // Verify composition
        assert_eq!(CPU_TYPE_POWERPC64, CPU_TYPE_POWERPC | CPU_ARCH_ABI64);
        assert_eq!(CPU_TYPE_X86_64, CPU_TYPE_X86 | CPU_ARCH_ABI64);
        assert_eq!(CPU_TYPE_ARM64, CPU_TYPE_ARM | CPU_ARCH_ABI64);
        assert_eq!(CPU_TYPE_ARM64_32, CPU_TYPE_ARM | CPU_ARCH_ABI64_32);

        // Bitness
        assert_eq!(cpu_type_bitness(CPU_TYPE_ARM64), 64);
        assert_eq!(cpu_type_bitness(CPU_TYPE_X86), 32);
        assert_eq!(cpu_type_bitness(CPU_TYPE_X86_64), 64);
        assert_eq!(cpu_type_bitness(CPU_TYPE_ARM), 32);
        assert_eq!(cpu_type_bitness(CPU_TYPE_POWERPC), 32);
        assert_eq!(cpu_type_bitness(CPU_TYPE_POWERPC64), 64);
        assert_eq!(cpu_type_bitness(CPU_TYPE_ARM64_32), 32);

        // Names
        assert_eq!(cpu_type_name(CPU_TYPE_ARM64), "ARM64");
        assert_eq!(cpu_type_name(CPU_TYPE_POWERPC), "POWERPC");
        assert_eq!(cpu_type_name(CPU_TYPE_ANY), "ANY");
    }

    #[test]
    fn test_cpu_subtype_names() {
        let n = cpu_subtype_name(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
        assert_eq!(n, "ALL");

        let n = cpu_subtype_name(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
        assert_eq!(n, "ARM64E");

        let n = cpu_subtype_name(CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_970);
        assert_eq!(n, "970 (G5)");
    }

    // ── File Types ─────────────────────────────────────────────────────────

    #[test]
    fn test_file_type_names() {
        assert_eq!(file_type_name(MH_OBJECT), "OBJECT");
        assert_eq!(file_type_name(MH_EXECUTE), "EXECUTE");
        assert_eq!(file_type_name(MH_DYLIB), "DYLIB");
        assert_eq!(file_type_name(MH_BUNDLE), "BUNDLE");
        assert_eq!(file_type_name(MH_DYLINKER), "DYLINKER");
        assert_eq!(file_type_name(MH_DSYM), "DSYM");
        assert_eq!(file_type_name(MH_KEXT_BUNDLE), "KEXT_BUNDLE");
        assert_eq!(file_type_name(MH_FILESET), "FILESET");
        assert_eq!(file_type_name(MH_DYLIB_STUB), "DYLIB_STUB");
        assert_eq!(file_type_name(MH_CORE), "CORE");
        assert_eq!(file_type_name(9999), "UNKNOWN");

        assert_eq!(file_type_description(MH_EXECUTE), "Demand Paged Executable File");
        assert_eq!(file_type_description(MH_DYLIB), "Dynamically Bound Shared Library");
    }

    // ── Header Flags ───────────────────────────────────────────────────────

    #[test]
    fn test_header_flag_names() {
        let flags = MH_PIE | MH_NO_HEAP_EXECUTION;
        let names = header_flag_names(flags);
        assert!(names.contains(&"PIE"));
        assert!(names.contains(&"NO_HEAP_EXECUTION"));
        assert!(!names.contains(&"DYLDLINK"));

        let all_off = header_flag_names(0);
        assert!(all_off.is_empty());
    }

    // ── Load Command Names ─────────────────────────────────────────────────

    #[test]
    fn test_load_command_names() {
        assert_eq!(load_command_name(LC_SEGMENT_64), "LC_SEGMENT_64");
        assert_eq!(load_command_name(LC_SYMTAB), "LC_SYMTAB");
        assert_eq!(load_command_name(LC_MAIN), "LC_MAIN");
        assert_eq!(load_command_name(LC_BUILD_VERSION), "LC_BUILD_VERSION");
        assert_eq!(load_command_name(LC_DYLD_CHAINED_FIXUPS), "LC_DYLD_CHAINED_FIXUPS");
        assert_eq!(load_command_name(LC_DYLD_EXPORTS_TRIE), "LC_DYLD_EXPORTS_TRIE");
        assert_eq!(load_command_name(LC_RPATH), "LC_RPATH");
        assert_eq!(load_command_name(LC_UUID), "LC_UUID");
    }

    // ── VM Protection ──────────────────────────────────────────────────────

    #[test]
    fn test_vm_prot_string() {
        assert_eq!(vm_prot_string(VM_PROT_NONE), "NONE");
        assert_eq!(vm_prot_string(VM_PROT_READ), "R");
        assert_eq!(vm_prot_string(VM_PROT_READ | VM_PROT_WRITE), "RW");
        assert_eq!(vm_prot_string(VM_PROT_READ | VM_PROT_EXECUTE), "RX");
        assert_eq!(
            vm_prot_string(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE),
            "RWX"
        );
    }

    // ── Section Types / Attributes ─────────────────────────────────────────

    #[test]
    fn test_section_type_names() {
        assert_eq!(section_type_name(S_REGULAR), "REGULAR");
        assert_eq!(section_type_name(S_ZEROFILL), "ZEROFILL");
        assert_eq!(section_type_name(S_CSTRING_LITERALS), "CSTRING_LITERALS");
        assert_eq!(section_type_name(S_LAZY_SYMBOL_POINTERS), "LAZY_SYMBOL_POINTERS");
        assert_eq!(section_type_name(S_INTERPOSING), "INTERPOSING");
        assert_eq!(section_type_name(S_COALESCED), "COALESCED");
    }

    #[test]
    fn test_section_attribute_names() {
        let names = section_attribute_names(S_ATTR_PURE_INSTRUCTIONS | S_ATTR_DEBUG);
        assert!(names.contains(&"PURE_INSTRUCTIONS"));
        assert!(names.contains(&"DEBUG"));
        assert!(!names.contains(&"NO_DEAD_STRIP"));
    }

    // ── Platforms / Tools ──────────────────────────────────────────────────

    #[test]
    fn test_platform_names() {
        assert_eq!(platform_name(PLATFORM_MACOS), "MACOS");
        assert_eq!(platform_name(PLATFORM_IOS), "IOS");
        assert_eq!(platform_name(PLATFORM_IOSSIMULATOR), "IOSSIMULATOR");
        assert_eq!(platform_name(PLATFORM_DRIVERKIT), "DRIVERKIT");
        assert_eq!(platform_name(PLATFORM_VISIONOS), "VISIONOS");
        assert_eq!(platform_name(PLATFORM_BRIDGEOS), "BRIDGEOS");
    }

    #[test]
    fn test_tool_names() {
        assert_eq!(tool_name(TOOL_CLANG), "CLANG");
        assert_eq!(tool_name(TOOL_SWIFT), "SWIFT");
        assert_eq!(tool_name(TOOL_LD), "LD");
        assert_eq!(tool_name(TOOL_LLD), "LLD");
    }

    // ── Version String ─────────────────────────────────────────────────────

    #[test]
    fn test_version_string() {
        assert_eq!(DylibCommand::version_string(0x000d0000), "13.0.0");
        assert_eq!(DylibCommand::version_string(0x000e0003), "14.0.3");
        assert_eq!(DylibCommand::version_string(0x000f0000), "15.0.0");
        assert_eq!(DylibCommand::version_string(0x00000000), "0.0.0");
    }

    #[test]
    fn test_source_version() {
        let sv = SourceVersionCommand { version: 0 };
        assert_eq!(sv.version_string(), "0.0.0.0.0");
    }

    // ── UUID Display ───────────────────────────────────────────────────────

    #[test]
    fn test_uuid_display() {
        let uuid_bytes: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        ];
        let uc = UuidCommand { uuid: uuid_bytes };
        let s = format!("{}", uc);
        assert_eq!(s, "DEADBEEF-CAFE-BABE-1234-56789ABCDEF0");
    }

    // ── Code Signature Magic Names ─────────────────────────────────────────

    #[test]
    fn test_cs_magic_names() {
        assert_eq!(cs_magic_name(CSMAGIC_REQUIREMENT), "CSMAGIC_REQUIREMENT");
        assert_eq!(cs_magic_name(CSMAGIC_ENTITLEMENTS), "CSMAGIC_ENTITLEMENTS");
        assert_eq!(cs_magic_name(CSMAGIC_BLOBWRAPPER), "CSMAGIC_BLOBWRAPPER");
        assert_eq!(cs_magic_name(CSMAGIC_EMBEDDED_SIGNATURE), "CSMAGIC_EMBEDDED_SIGNATURE");
        assert_eq!(cs_magic_name(0xDEADBEEF), "UNKNOWN");
    }

    // ── Chained Fixups ─────────────────────────────────────────────────────

    #[test]
    fn test_chained_ptr_format_names() {
        assert_eq!(chained_ptr_format_name(DYLD_CHAINED_PTR_ARM64E), "PTR_ARM64E");
        assert_eq!(chained_ptr_format_name(DYLD_CHAINED_PTR_64), "PTR_64");
        assert_eq!(chained_ptr_format_name(DYLD_CHAINED_PTR_X86_64_USERLAND), "PTR_X86_64_USERLAND");
        assert_eq!(chained_ptr_format_name(9999), "UNKNOWN");
    }

    // ── ULEB128 / SLEB128 ──────────────────────────────────────────────────

    #[test]
    fn test_uleb128_decode() {
        assert_eq!(decode_uleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_uleb128(&[0x01]).unwrap(), (1, 1));
        assert_eq!(decode_uleb128(&[0x7f]).unwrap(), (127, 1));
        assert_eq!(decode_uleb128(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(decode_uleb128(&[0xe5, 0x8e, 0x26]).unwrap(), (624485, 3));
        assert_eq!(decode_uleb128(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]).unwrap(), (u64::MAX, 10));
    }

    #[test]
    fn test_sleb128_decode() {
        assert_eq!(decode_sleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_sleb128(&[0x01]).unwrap(), (1, 1));
        assert_eq!(decode_sleb128(&[0x7f]).unwrap(), (-1, 1));
        assert_eq!(decode_sleb128(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(decode_sleb128(&[0x7e]).unwrap(), (-2, 1));
    }

    // ── Padded String ──────────────────────────────────────────────────────

    #[test]
    fn test_padded_string() {
        // For this we test indirectly via segment parsing.
        // `read_padded_string` is private, so we test through structures.
        let buf = [b'_', b'_', b'T', b'E', b'X', b'T', 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let s = read_padded_string(&buf, 16);
        assert_eq!(s, "__TEXT");
    }

    // ── FAT Binary ─────────────────────────────────────────────────────────

    #[test]
    fn test_fat_binary_be() {
        let mut data = Vec::new();
        data.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes()); // 1 arch
        // arch entry
        data.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
        data.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_be_bytes());
        data.extend_from_slice(&0x1000u32.to_be_bytes());
        data.extend_from_slice(&0x10000u32.to_be_bytes());
        data.extend_from_slice(&14u32.to_be_bytes()); // 2^14

        let fat = parse_fat(&data).expect("Should parse FAT binary (BE)");
        assert_eq!(fat.arches.len(), 1);
        assert_eq!(fat.arches[0].cputype, CPU_TYPE_ARM64);
        assert_eq!(fat.arches[0].cpusubtype, CPU_SUBTYPE_ARM64_ALL);
        assert_eq!(fat.arches[0].offset, 0x1000);
        assert_eq!(fat.arches[0].size, 0x10000);
        assert_eq!(fat.arches[0].align, 14);
        assert_eq!(fat.arches[0].cpu_name(), "ARM64");
        assert_eq!(fat.arches[0].bitness(), 64);
    }

    #[test]
    fn test_fat_binary_le() {
        let mut data = Vec::new();
        data.extend_from_slice(&FAT_CIGAM.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes()); // 2 arches

        // Arch 1: x86_64
        data.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        data.extend_from_slice(&CPU_SUBTYPE_X86_ALL.to_le_bytes());
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x5000u32.to_le_bytes());
        data.extend_from_slice(&12u32.to_le_bytes());

        // Arch 2: arm64
        data.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        data.extend_from_slice(&CPU_SUBTYPE_ARM64E.to_le_bytes());
        data.extend_from_slice(&0x6000u32.to_le_bytes());
        data.extend_from_slice(&0x8000u32.to_le_bytes());
        data.extend_from_slice(&14u32.to_le_bytes());

        let fat = parse_fat(&data).expect("Should parse FAT binary (LE)");
        assert_eq!(fat.arches.len(), 2);
        assert_eq!(fat.num_arches(), 2);
        assert_eq!(fat.arches[0].cputype, CPU_TYPE_X86_64);
        assert_eq!(fat.arches[1].cputype, CPU_TYPE_ARM64);

        // find_arch
        let x86 = fat.find_arch(CPU_TYPE_X86_64);
        assert!(x86.is_some());
        assert_eq!(x86.unwrap().size, 0x5000);

        let arm = fat.find_arch(CPU_TYPE_ARM64);
        assert!(arm.is_some());
        assert_eq!(arm.unwrap().cpusubtype, CPU_SUBTYPE_ARM64E);

        // cpu_types
        let types = fat.cpu_types();
        assert_eq!(types, vec![CPU_TYPE_ARM64, CPU_TYPE_X86_64]);
    }

    #[test]
    fn test_fat_binary_invalid_magic() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xdeadbeefu32.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        let result = parse_fat(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_fat_binary_truncated() {
        let result = parse_fat(&[0xca, 0xfe, 0xba, 0xbe]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fat_binary_zero_arches() {
        let mut data = Vec::new();
        data.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let result = parse_fat(&data);
        assert!(result.is_err());
    }

    // ── Export Trie ────────────────────────────────────────────────────────

    #[test]
    fn test_empty_export_trie() {
        let trie = parse_export_trie(&[]).expect("Should handle empty data");
        assert!(trie.entries.is_empty());
    }

    #[test]
    fn test_export_trie_single_entry() {
        // Minimal export trie:
        //   terminal_size = 3 (flags uleb + address uleb)
        //     flags = 0 (1 byte: 0x00)
        //     address = 0x1000 (2 bytes: 0x80 0x20)
        //   children count = 0 (1 byte: 0x00)
        let trie_data = [0x03u8, 0x00, 0x80, 0x20, 0x00];
        let trie = parse_export_trie(&trie_data).expect("Should parse");
        assert!(!trie.entries.is_empty());
        let entry = &trie.entries[0];
        assert_eq!(entry.address, 0x1000);
        assert_eq!(entry.flags, 0);
        assert!(entry.name.is_empty()); // root node
    }

    #[test]
    fn test_export_trie_with_children() {
        // Node at offset 0:
        //   terminal_size = 0 (1 byte: 0x00)
        //   children_count = 1 (1 byte: 0x01)
        //   child_label = "_" + NUL (2 bytes: 0x5f 0x00)
        //   child_offset = 10 (1 byte: 0x0a)
        // Node at offset 10:
        //   terminal_size = 3 (1 byte: 0x03)
        //     flags = 0 (1 byte: 0x00)
        //     address = 0x2000 (2 bytes: 0x80 0x40)
        //   children_count = 0 (1 byte: 0x00)
        // Total data:
        //   [0x00, 0x01, 0x5f, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x40, 0x00]
        // Offsets:  0     2            5        6-9(pad)    10   11    12    14   15
        // Let me recalculate: node at 0: terminal_size(0)=0x00 => 1 byte
        //   children_count=0x01 => 1 byte at offset 1
        //   label "_" + NUL => 2 bytes at offset 2-3
        //   child_offset=10 as uleb => 0x0a => 1 byte at offset 4
        // Total node 0: 5 bytes (indices 0-4)
        // Node at offset 10 (we need padding to 10):
        //   indices 5-9 = 0x00 padding
        //   terminal_size=3 => 0x03 at index 10
        //   flags=0 => 0x00 at index 11
        //   address=0x2000 => 0x80 0x40 at indices 12-13
        //   children_count=0 => 0x00 at index 14
        let mut trie_data = vec![0x00u8, 0x01, 0x5f, 0x00, 0x0a]; // node 0
        trie_data.extend_from_slice(&[0x00; 5]);                  // padding to offset 10
        trie_data.extend_from_slice(&[0x03u8, 0x00, 0x80, 0x40, 0x00]); // node at 10

        let trie = parse_export_trie(&trie_data).expect("Should parse");
        assert!(!trie.entries.is_empty());
        // The child is at offset 10 with prefix "_" => name = "_"
        let entry = trie.entries.iter().find(|e| e.name == "_");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().address, 0x2000);
    }

    // ── NList / Symbol Table ─────────────────────────────────────────────

    #[test]
    fn test_nlist_constants() {
        // Basic N_TYPE extraction
        assert_eq!(N_SECT, 0xe);
        assert_eq!(N_UNDF, 0x0);
        assert_eq!(N_EXT, 0x1);

        let sym = NList {
            n_strx: 10,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: N_WEAK_DEF,
            n_value: 0x1000,
        };
        assert!(sym.is_section());
        assert!(sym.is_external());
        assert!(sym.is_weak_def());
        assert!(!sym.is_undefined());
        assert!(!sym.is_stab());
        assert_eq!(sym.entry_size(true), 16);
        assert_eq!(sym.entry_size(false), 12);
    }

    #[test]
    fn test_symbol_name() {
        let strings = b"__mh_execute_header\0_main\0_printf\0";
        let nlist = NList {
            n_strx: 0,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0x1000,
        };
        assert_eq!(symbol_name(&nlist, strings), "");

        let nlist2 = NList {
            n_strx: 20,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0x2000,
        };
        assert_eq!(symbol_name(&nlist2, strings), "_main");

        let nlist3 = NList {
            n_strx: 26,
            n_type: N_UNDF | N_EXT,
            n_sect: NO_SECT,
            n_desc: 0,
            n_value: 0,
        };
        assert_eq!(symbol_name(&nlist3, strings), "_printf");
    }

    // ── Section ────────────────────────────────────────────────────────────

    #[test]
    fn test_section_methods() {
        let sec = Section {
            sectname: "__text".into(),
            segname: "__TEXT".into(),
            addr: 0x100000000,
            size: 0x1000,
            offset: 0x4000,
            align: 4,
            reloff: 0,
            nreloc: 0,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };

        assert_eq!(sec.section_type(), S_REGULAR);
        assert!(sec.is_pure_instructions());
        assert!(sec.is_some_instructions());
        assert!(sec.is_execute());
        assert!(sec.is_code());
        assert_eq!(sec.type_name(), "REGULAR");

        let zerofill = Section {
            sectname: "__bss".into(),
            segname: "__DATA".into(),
            addr: 0,
            size: 0x100,
            offset: 0,
            align: 0,
            reloff: 0,
            nreloc: 0,
            flags: S_ZEROFILL,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };
        assert!(zerofill.is_zerofill());
        assert_eq!(zerofill.section_type(), S_ZEROFILL);
    }

    // ── Segment ────────────────────────────────────────────────────────────

    #[test]
    fn test_segment_methods() {
        let seg = SegmentCommand {
            segname: "__TEXT".into(),
            vmaddr: 0x100000000,
            vmsize: 0x10000,
            fileoff: 0,
            filesize: 0x10000,
            maxprot: VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
            initprot: VM_PROT_READ | VM_PROT_EXECUTE,
            nsects: 3,
            flags: SG_PROTECTED_VERSION_1,
        };

        assert!(seg.is_readable());
        assert!(!seg.is_writable());
        assert!(seg.is_executable());
        assert!(seg.is_apple_protected());
        assert_eq!(seg.initprot_string(), "RX");
        assert_eq!(seg.maxprot_string(), "RWX");
    }

    // ── MachHeader ─────────────────────────────────────────────────────────

    #[test]
    fn test_mach_header_methods() {
        let hdr = MachHeader {
            magic: MH_CIGAM_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64E,
            filetype: MH_EXECUTE,
            ncmds: 20,
            sizeofcmds: 0x1000,
            flags: MH_PIE | MH_NO_HEAP_EXECUTION | MH_DYLDLINK,
            reserved: 0,
        };
        assert!(hdr.is_64bit());
        assert!(hdr.is_le());
        assert_eq!(hdr.bitness(), 64);
        assert_eq!(hdr.cpu_name(), "ARM64");
        assert_eq!(hdr.cpu_subtype_name(), "ARM64E");
        assert_eq!(hdr.file_type_name(), "EXECUTE");
        assert!(hdr.is_executable());
        assert!(!hdr.is_dylib());
        assert!(!hdr.is_dsym());
    }

    // ── LoadCommand Name ───────────────────────────────────────────────────

    #[test]
    fn test_load_command_variant_name() {
        let lc = LoadCommand::Main(MainCommand {
            entryoff: 0x1000,
            stacksize: 0,
        });
        assert_eq!(lc.name(), "LC_MAIN");

        let lc = LoadCommand::Uuid(UuidCommand { uuid: [0u8; 16] });
        assert_eq!(lc.name(), "LC_UUID");

        let lc = LoadCommand::BuildVersion(BuildVersionCommand {
            platform: PLATFORM_IOS,
            minos: 0x000e0000,
            sdk: 0x000f0000,
            ntools: 1,
            tools: vec![BuildToolVersion {
                tool: TOOL_CLANG,
                version: 0x000f0000,
            }],
        });
        assert_eq!(lc.name(), "LC_BUILD_VERSION");

        let lc = LoadCommand::Unknown {
            cmd: 0xDEAD,
            cmdsize: 8,
            data: vec![],
        };
        assert!(lc.name().contains("LC_UNKNOWN"));
    }

    // ── MachOFile Accessors ────────────────────────────────────────────────

    #[test]
    fn test_macho_uuider() {
        let mf = MachOFile {
            header: MachHeader {
                magic: MH_CIGAM_64,
                cputype: CPU_TYPE_X86_64,
                cpusubtype: CPU_SUBTYPE_X86_ALL,
                filetype: MH_EXECUTE,
                ncmds: 1,
                sizeofcmds: 0,
                flags: 0,
                reserved: 0,
            },
            commands: vec![LoadCommand::Uuid(UuidCommand {
                uuid: [0xAA; 16],
            })],
            sections: vec![],
            symbols: vec![],
            strings: vec![],
        };
        let uuid = mf.uuid().expect("Should find UUID");
        assert_eq!(uuid.uuid, [0xAA; 16]);
        assert!(mf.entry_point().is_none());
        assert!(mf.dylibs().is_empty());
    }

    // ── Build Version ──────────────────────────────────────────────────────

    #[test]
    fn test_build_version() {
        let bv = BuildVersionCommand {
            platform: PLATFORM_MACOS,
            minos: 0x000e0000, // 14.0.0
            sdk: 0x000e0003,   // 14.0.3
            ntools: 1,
            tools: vec![BuildToolVersion {
                tool: TOOL_LD,
                version: 0x000f0000,
            }],
        };
        assert_eq!(bv.platform_name(), "MACOS");
        assert_eq!(bv.minos_string(), "14.0.0");
        assert_eq!(bv.sdk_string(), "14.0.3");
        assert_eq!(bv.tools[0].tool_name(), "LD");
        assert_eq!(bv.tools[0].version_string(), "15.0.0");
    }

    // ── Error Display ──────────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", MachError::InvalidMagic(0xdeadbeef)),
            "Invalid Mach-O magic: 0xdeadbeef"
        );
        assert_eq!(
            format!("{}", MachError::TooManyCommands),
            "Too many load commands"
        );
        assert_eq!(
            format!("{}", MachError::TruncatedData),
            "Truncated data"
        );
        assert_eq!(
            format!("{}", MachError::CircularExportTrie),
            "Circular reference in export trie"
        );
    }

    // ── Code Signature ──────────────────────────────────────────────────────

    #[test]
    fn test_code_signature_blob_wrapper() {
        // Build a minimal CSMAGIC_BLOBWRAPPER with one entitlement blob
        // Superblob:
        //   magic = CSMAGIC_BLOBWRAPPER (4 bytes) = 0xfade0b01
        //   length = 44 (4 bytes)
        //   count = 1 (4 bytes)
        //   index[0]:
        //     type = CSMAGIC_ENTITLEMENTS (4 bytes) = 0xfade7171
        //     offset = 20 (4 bytes)
        //   Entitlement blob at offset 20:
        //     magic = CSMAGIC_ENTITLEMENTS (4 bytes)
        //     length = 24 (4 bytes)
        //     data = "<plist>...</plist>" (16 bytes)
        let mut data = Vec::new();
        data.extend_from_slice(&CSMAGIC_BLOBWRAPPER.to_be_bytes()); // magic
        data.extend_from_slice(&44u32.to_be_bytes());                // length
        data.extend_from_slice(&1u32.to_be_bytes());                 // count
        data.extend_from_slice(&CSMAGIC_ENTITLEMENTS.to_be_bytes()); // blob type
        data.extend_from_slice(&20u32.to_be_bytes());                // blob offset
        // Entitlement blob at offset 20:
        data.extend_from_slice(&CSMAGIC_ENTITLEMENTS.to_be_bytes()); // magic
        data.extend_from_slice(&24u32.to_be_bytes());                // length
        data.extend_from_slice(b"<plist></plist>\0\0");             // data (16)

        let cs = parse_code_signature(&data).expect("Should parse code signature");
        assert_eq!(cs.magic, CSMAGIC_BLOBWRAPPER);
        assert_eq!(cs.count, 1);
        assert_eq!(cs.blobs[0].blob_type, CSMAGIC_ENTITLEMENTS);

        let ents = parse_entitlements(&data).expect("Should parse entitlements");
        let ents_str = String::from_utf8_lossy(&ents.data);
        assert!(ents_str.starts_with("<plist>"));
    }

    #[test]
    fn test_code_signature_invalid() {
        let r = parse_code_signature(&[0; 8]);
        assert!(r.is_err());
    }

    // ── MachError From nom ─────────────────────────────────────────────────

    #[test]
    fn test_mach_error_from_nom() {
        let e: nom::Err<nom::error::Error<&[u8]>> =
            nom::Err::Error(nom::error::Error::new(&b""[..], nom::error::ErrorKind::Eof));
        let me = MachError::from(e);
        assert!(matches!(me, MachError::NomError(_)));
    }
}
