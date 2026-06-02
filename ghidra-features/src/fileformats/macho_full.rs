//! Complete Mach-O binary format parser.
//!
//! Ported from Ghidra's Java Mach-O implementation:
//! `ghidra.app.util.bin.format.macho` package
//!
//! Supports:
//! - Universal (FAT) binaries
//! - 32-bit and 64-bit Mach-O files
//! - All standard load commands
//! - Export trie parsing
//! - DYLD opcode-based binding/rebase tables
//! - Chained fixups
//!
//! Reference: <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>

use std::collections::HashSet;
use std::fmt;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Magic Numbers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// PowerPC 32-bit Magic Number (big-endian)
pub const MH_MAGIC: u32 = 0xfeedface;
/// Intel x86 32-bit Magic Number (little-endian, byte-swapped MH_MAGIC)
pub const MH_CIGAM: u32 = 0xcefaedfe;
/// PowerPC 64-bit Magic Number (big-endian)
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
/// Intel x86 64-bit Magic Number (little-endian, byte-swapped MH_MAGIC_64)
pub const MH_CIGAM_64: u32 = 0xcffaedfe;
/// FAT/Universal binary magic (big-endian)
pub const FAT_MAGIC: u32 = 0xcafebabe;
/// FAT/Universal binary magic (little-endian, byte-swapped)
pub const FAT_CIGAM: u32 = 0xbebafeca;

/// Returns true if the given magic is a valid Mach-O magic number.
pub fn is_macho_magic(magic: u32) -> bool {
    matches!(magic, MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64)
}

/// Returns true if the magic indicates a 64-bit Mach-O.
pub fn is_macho_64(magic: u32) -> bool {
    matches!(magic, MH_MAGIC_64 | MH_CIGAM_64)
}

/// Returns true if the magic is little-endian (CIGAM variants).
pub fn is_macho_le(magic: u32) -> bool {
    matches!(magic, MH_CIGAM | MH_CIGAM_64)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CPU Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Mask for architecture bits in CPU type.
pub const CPU_ARCH_MASK: i32 = 0xff00_0000u32 as i32;
/// 64-bit ABI flag.
pub const CPU_ARCH_ABI64: i32 = 0x0100_0000u32 as i32;
/// ABI for 64-bit hardware with 32-bit types (LP32).
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

/// Return a human-readable name for a CPU type.
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

/// Return the bitness of a CPU type (32 or 64).
pub fn cpu_type_bitness(cpu_type: i32) -> u8 {
    match cpu_type {
        CPU_TYPE_ARM | CPU_TYPE_SPARC | CPU_TYPE_I860 | CPU_TYPE_POWERPC | CPU_TYPE_X86
        | CPU_TYPE_ARM64_32 => 32,
        CPU_TYPE_ARM64 | CPU_TYPE_POWERPC64 | CPU_TYPE_X86_64 => 64,
        _ => {
            if (cpu_type & CPU_ARCH_ABI64) != 0 {
                64
            } else {
                32
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CPU Subtypes
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// PowerPC subtypes
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

/// Build an Intel CPU subtype from family (f) and model (m).
pub const fn cpu_subtype_intel(f: i32, m: i32) -> i32 {
    f + (m << 4)
}

// x86 subtypes
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

// X86 subtypes
pub const CPU_SUBTYPE_X86_ALL: i32 = 3;
pub const CPU_SUBTYPE_X86_ARCH1: i32 = 4;
pub const CPU_THREADTYPE_INTEL_HTT: i32 = 1;

// ARM subtypes
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

// ARM64 subtypes
pub const CPU_SUBTYPE_ARM64_ALL: i32 = 0;
pub const CPU_SUBTYPE_ARM64_V8: i32 = 1;
pub const CPU_SUBTYPE_ARM64E: i32 = 2;

// Misc
pub const CPU_SUBTYPE_MULTIPLE: i32 = -1;
pub const CPU_SUBTYPE_LITTLE_ENDIAN: i32 = 0;
pub const CPU_SUBTYPE_BIG_ENDIAN: i32 = 1;

// SPARC subtypes
pub const CPU_SUBTYPE_SPARC_ALL: i32 = 0;

// I860 subtypes
pub const CPU_SUBTYPE_I860_ALL: i32 = 0;
pub const CPU_SUBTYPE_I860_860: i32 = 1;

// MIPS subtypes
pub const CPU_SUBTYPE_MIPS_ALL: i32 = 0;
pub const CPU_SUBTYPE_MIPS_R2300: i32 = 1;
pub const CPU_SUBTYPE_MIPS_R2600: i32 = 2;
pub const CPU_SUBTYPE_MIPS_R2800: i32 = 3;
pub const CPU_SUBTYPE_MIPS_R2000A: i32 = 4;
pub const CPU_SUBTYPE_MIPS_R2000: i32 = 5;
pub const CPU_SUBTYPE_MIPS_R3000A: i32 = 6;
pub const CPU_SUBTYPE_MIPS_R3000: i32 = 7;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// File Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Relocatable object file.
pub const MH_OBJECT: u32 = 0x1;
/// Demand paged executable file.
pub const MH_EXECUTE: u32 = 0x2;
/// Fixed VM shared library file.
pub const MH_FVMLIB: u32 = 0x3;
/// Core file.
pub const MH_CORE: u32 = 0x4;
/// Preloaded executable file.
pub const MH_PRELOAD: u32 = 0x5;
/// Dynamically bound shared library.
pub const MH_DYLIB: u32 = 0x6;
/// Dynamic link editor.
pub const MH_DYLINKER: u32 = 0x7;
/// Dynamically bound bundle file.
pub const MH_BUNDLE: u32 = 0x8;
/// Shared library stub for static linking only, no section contents.
pub const MH_DYLIB_STUB: u32 = 0x9;
/// Linking only, companion file with only debug sections.
pub const MH_DSYM: u32 = 0xa;
/// x86_64 kexts.
pub const MH_KEXT_BUNDLE: u32 = 0xb;
/// Kernel cache fileset.
pub const MH_FILESET: u32 = 0xc;

/// Return the name of a file type.
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

/// Return a human-readable description of a file type.
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
        MH_KEXT_BUNDLE => "x86 64 Kernel Extension",
        MH_FILESET => "Kernel Cache Fileset",
        _ => "Unrecognized file type",
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Header Flags
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const MH_NOUNDEFS: u32 = 0x1;
pub const MH_INCRLINK: u32 = 0x2;
pub const MH_DYLDLINK: u32 = 0x4;
pub const MH_BINDATLOAD: u32 = 0x8;
pub const MH_PREBOUND: u32 = 0x10;
pub const MH_SPLIT_SEGS: u32 = 0x20;
pub const MH_LAZY_INIT: u32 = 0x40;
pub const MH_TWOLEVEL: u32 = 0x80;
pub const MH_FORCE_FLAT: u32 = 0x100;
pub const MH_NOMULTIDEFS: u32 = 0x200;
pub const MH_NOFIXPREBINDING: u32 = 0x400;
pub const MH_PREBINDABLE: u32 = 0x800;
pub const MH_ALLMODSBOUND: u32 = 0x1000;
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
pub const MH_CANONICAL: u32 = 0x4000;
pub const MH_WEAK_DEFINES: u32 = 0x8000;
pub const MH_BINDS_TO_WEAK: u32 = 0x10000;
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;
pub const MH_ROOT_SAFE: u32 = 0x40000;
pub const MH_SETUID_SAFE: u32 = 0x80000;
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x100000;
pub const MH_PIE: u32 = 0x200000;
pub const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x400000;
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x800000;
pub const MH_NO_HEAP_EXECUTION: u32 = 0x1000000;
pub const MH_APP_EXTENSION_SAFE: u32 = 0x2000000;
pub const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO: u32 = 0x04000000;
pub const MH_SIM_SUPPORT: u32 = 0x08000000;
pub const MH_DYLIB_IN_CACHE: u32 = 0x80000000;

/// List of all known header flag names with their values.
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
    (
        MH_NLIST_OUTOFSYNC_WITH_DYLDINFO,
        "NLIST_OUTOFSYNC_WITH_DYLDINFO",
    ),
    (MH_SIM_SUPPORT, "SIM_SUPPORT"),
    (MH_DYLIB_IN_CACHE, "DYLIB_IN_CACHE"),
];

/// Return the names of all header flags that are set.
pub fn header_flag_names(flags: u32) -> Vec<&'static str> {
    HEADER_FLAG_NAMES
        .iter()
        .filter_map(|&(v, name)| if (flags & v) != 0 { Some(name) } else { None })
        .collect()
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Load Command Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// If set in the load command type, the dynamic linker must understand this command.
pub const LC_REQ_DYLD: u32 = 0x8000_0000;

pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_SYMSEG: u32 = 0x3;
pub const LC_THREAD: u32 = 0x4;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_LOADFVMLIB: u32 = 0x6;
pub const LC_IDFVMLIB: u32 = 0x7;
pub const LC_IDENT: u32 = 0x8;
pub const LC_FVMFILE: u32 = 0x9;
pub const LC_PREPAGE: u32 = 0xa;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_ID_DYLINKER: u32 = 0xf;
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
pub const LC_ROUTINES: u32 = 0x11;
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
pub const LC_SUB_UMBRELLA: u32 = 0x13;
pub const LC_SUB_CLIENT: u32 = 0x14;
pub const LC_SUB_LIBRARY: u32 = 0x15;
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
pub const LC_PREBIND_CKSUM: u32 = 0x17;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_ROUTINES_64: u32 = 0x1a;
pub const LC_UUID: u32 = 0x1b;
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2a;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
pub const LC_LINKER_OPTIONS: u32 = 0x2d;
pub const LC_OPTIMIZATION_HINT: u32 = 0x2e;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_NOTE: u32 = 0x31;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;

// Base constants for pattern matching (without LC_REQ_DYLD bit).
pub const LC_LOAD_WEAK_DYLIB_BASE: u32 = 0x18;
pub const LC_RPATH_BASE: u32 = 0x1c;
pub const LC_REEXPORT_DYLIB_BASE: u32 = 0x1f;
pub const LC_DYLD_INFO_ONLY_BASE: u32 = 0x22;
pub const LC_LOAD_UPWARD_DYLIB_BASE: u32 = 0x23;
pub const LC_MAIN_BASE: u32 = 0x28;
pub const LC_DYLD_EXPORTS_TRIE_BASE: u32 = 0x33;
pub const LC_DYLD_CHAINED_FIXUPS_BASE: u32 = 0x34;
pub const LC_FILESET_ENTRY_BASE: u32 = 0x35;

/// Return the name of a load command type.
pub fn load_command_name(cmd: u32) -> String {
    // Check exact values first (those with LC_REQ_DYLD differ from their base)
    let exact_name = match cmd {
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
        LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
        LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
        LC_LOAD_UPWARD_DYLIB => "LC_LOAD_UPWARD_DYLIB",
        LC_MAIN => "LC_MAIN",
        LC_RPATH => "LC_RPATH",
        LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE",
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
        LC_FILESET_ENTRY => "LC_FILESET_ENTRY",
        _ => "",
    };
    if !exact_name.is_empty() {
        return exact_name.to_string();
    }

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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Segment Protection Flags
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const VM_PROT_NONE: i32 = 0x0;
pub const VM_PROT_READ: i32 = 0x1;
pub const VM_PROT_WRITE: i32 = 0x2;
pub const VM_PROT_EXECUTE: i32 = 0x4;

/// Segment flag: Apple protected.
pub const SG_PROTECTED_VERSION_1: u32 = 0x8;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Section Types and Attributes
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Mask for the section type field.
pub const SECTION_TYPE_MASK: u32 = 0x0000_00ff;

/// Regular section.
pub const S_REGULAR: u32 = 0x0;
/// Zero fill on demand.
pub const S_ZEROFILL: u32 = 0x1;
/// Section with only literal C strings.
pub const S_CSTRING_LITERALS: u32 = 0x2;
/// Section with only 4-byte literals.
pub const S_4BYTE_LITERALS: u32 = 0x3;
/// Section with only 8-byte literals.
pub const S_8BYTE_LITERALS: u32 = 0x4;
/// Section with only pointers to literals.
pub const S_LITERAL_POINTERS: u32 = 0x5;
/// Section with non-lazy symbol pointers.
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
/// Section with lazy symbol pointers.
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
/// Section with symbol stubs.
pub const S_SYMBOL_STUBS: u32 = 0x8;
/// Section with function pointers for initialization.
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
/// Section with function pointers for termination.
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;
/// Section with coalesced symbols.
pub const S_COALESCED: u32 = 0xb;
/// Zero fill (can be larger than 4GB).
pub const S_GB_ZEROFILL: u32 = 0xc;
/// Section with pairs of function pointers for interposing.
pub const S_INTERPOSING: u32 = 0xd;
/// Section with only 16-byte literals.
pub const S_16BYTE_LITERALS: u32 = 0xe;
/// DTrace Object Format section.
pub const S_DTRACE_DOF: u32 = 0xf;
/// Lazy-loaded dylib symbol pointers.
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
/// Thread-local regular.
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
/// Thread-local zerofill.
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
/// Thread-local variables.
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
/// Thread-local variable pointers.
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
/// Thread-local init function pointers.
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;

/// Return the name of a section type.
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Section Attributes
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Mask for the section attributes field.
pub const SECTION_ATTRIBUTES_MASK: u32 = 0xffff_ff00;
/// User-settable attributes.
pub const SECTION_ATTRIBUTES_USR: u32 = 0xff00_0000;
/// System-settable attributes.
pub const SECTION_ATTRIBUTES_SYS: u32 = 0x00ff_ff00;

pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
pub const S_ATTR_NO_TOC: u32 = 0x4000_0000;
pub const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x2000_0000;
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;
pub const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x0400_0000;
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
pub const S_ATTR_EXT_RELOC: u32 = 0x0000_0200;
pub const S_ATTR_LOC_RELOC: u32 = 0x0000_0100;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// NList (Symbol Table) Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Mask for debugger (STAB) bits.
pub const N_STAB: u8 = 0xe0;
/// Private external symbol bit.
pub const N_PEXT: u8 = 0x10;
/// Mask for the type bits.
pub const N_TYPE: u8 = 0x0e;
/// External symbol bit (global).
pub const N_EXT: u8 = 0x01;

/// Undefined symbol.
pub const N_UNDF: u8 = 0x0;
/// Absolute symbol.
pub const N_ABS: u8 = 0x2;
/// Defined in section.
pub const N_SECT: u8 = 0xe;
/// Prebound undefined (defined in a dylib).
pub const N_PBUD: u8 = 0xc;
/// Indirect symbol.
pub const N_INDR: u8 = 0xa;

/// Symbol is not in any section.
pub const NO_SECT: u8 = 0;

/// Reference type bitmask in n_desc.
pub const REFERENCE_TYPE: u16 = 0x7;
pub const REFERENCE_FLAG_UNDEFINED_NON_LAZY: u16 = 0x0;
pub const REFERENCE_FLAG_UNDEFINED_LAZY: u16 = 0x1;
pub const REFERENCE_FLAG_DEFINED: u16 = 0x2;
pub const REFERENCE_FLAG_PRIVATE_DEFINED: u16 = 0x3;
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY: u16 = 0x4;
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY: u16 = 0x5;

pub const REFERENCED_DYNAMICALLY: u16 = 0x0010;
pub const N_DESC_DISCARDED: u16 = 0x0020;
pub const N_WEAK_REF: u16 = 0x0040;
pub const N_WEAK_DEF: u16 = 0x0080;
pub const N_REF_TO_WEAK: u16 = 0x0080;
pub const N_ARM_THUMB_DEF: u16 = 0x0008;

// Library ordinals
pub const SELF_LIBRARY_ORDINAL: u8 = 0x00;
pub const MAX_LIBRARY_ORDINAL: u8 = 0xfd;
pub const DYNAMIC_LOOKUP_ORDINAL: u8 = 0xfe;
pub const EXECUTABLE_ORDINAL: u8 = 0xff;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Dynamic Symbol Table Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
pub const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DYLD Rebase / Bind Opcode Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const REBASE_TYPE_POINTER: u8 = 1;
pub const REBASE_TYPE_TEXT_ABSOLUTE32: u8 = 2;
pub const REBASE_TYPE_TEXT_PCREL32: u8 = 3;

pub const REBASE_OPCODE_MASK: u8 = 0xF0;
pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
pub const REBASE_OPCODE_DONE: u8 = 0x00;
pub const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

pub const BIND_TYPE_POINTER: u8 = 1;
pub const BIND_TYPE_TEXT_ABSOLUTE32: u8 = 2;
pub const BIND_TYPE_TEXT_PCREL32: u8 = 3;

pub const BIND_SPECIAL_DYLIB_SELF: i64 = 0;
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i64 = -1;
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i64 = -2;
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: i64 = -3;

pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x1;
pub const BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: u8 = 0x8;

pub const BIND_OPCODE_MASK: u8 = 0xF0;
pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;
pub const BIND_OPCODE_DONE: u8 = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
pub const BIND_OPCODE_THREADED: u8 = 0xD0;
pub const BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: u8 = 0x00;
pub const BIND_SUBOPCODE_THREADED_APPLY: u8 = 0x01;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Export Symbol Flags
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Build Version Platforms
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const PLATFORM_MACOS: u32 = 1;
pub const PLATFORM_IOS: u32 = 2;
pub const PLATFORM_TVOS: u32 = 3;
pub const PLATFORM_WATCHOS: u32 = 4;
pub const PLATFORM_BRIDGEOS: u32 = 5;
pub const PLATFORM_MACCATALYST: u32 = 6;
pub const PLATFORM_IOSSIMULATOR: u32 = 7;
pub const PLATFORM_TVOSSIMULATOR: u32 = 8;
pub const PLATFORM_WATCHOSSIMULATOR: u32 = 9;
pub const PLATFORM_DRIVERKIT: u32 = 10;
pub const PLATFORM_VISIONOS: u32 = 11;
pub const PLATFORM_VISIONOSSIMULATOR: u32 = 12;

/// Return the name of a build platform.
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Build Tools
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const TOOL_CLANG: u32 = 1;
pub const TOOL_SWIFT: u32 = 2;
pub const TOOL_LD: u32 = 3;
pub const TOOL_LLD: u32 = 4;

/// Return the name of a build tool.
pub fn tool_name(tool: u32) -> &'static str {
    match tool {
        TOOL_CLANG => "CLANG",
        TOOL_SWIFT => "SWIFT",
        TOOL_LD => "LD",
        TOOL_LLD => "LLD",
        _ => "UNKNOWN",
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Mach-O Error Type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Errors that can occur during Mach-O parsing.
#[derive(Debug, Clone)]
pub enum MachError {
    InvalidMagic(u32),
    InvalidHeader,
    TooManyCommands,
    InvalidCommandSize,
    TruncatedData,
    InvalidString,
    InvalidULEB,
    InvalidExportTrie,
    CircularExportTrie,
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
            MachError::InvalidULEB => write!(f, "Invalid ULEB128 encoding"),
            MachError::InvalidExportTrie => write!(f, "Invalid export trie"),
            MachError::CircularExportTrie => write!(f, "Circular reference in export trie"),
            MachError::NomError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for MachError {}

/// Type alias for Mach-O parse results.
pub type MachResult<T> = Result<T, MachError>;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper Functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Read exactly `n` bytes (length-prefixed in 16 bytes, trimmed by first NUL).
fn read_padded_string(data: &[u8], max_len: usize) -> String {
    let end = data
        .iter()
        .take(max_len)
        .position(|&b| b == 0)
        .unwrap_or(max_len);
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Decode a ULEB128 value from bytes, returning the value and the number of bytes consumed.
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

/// Decode an SLEB128 value from bytes, returning the value and the number of bytes consumed.
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
    // Sign extend
    if shift < 64 && (byte & 0x40) != 0 {
        result |= -(1i64 << shift);
    }
    // Find the number of bytes consumed
    let mut consumed = 1;
    for &b in data.iter() {
        if b & 0x80 == 0 {
            break;
        }
        consumed += 1;
    }
    Ok((result, consumed))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Data Structures
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct FatBinary {
    pub arches: Vec<FatArch>,
}

#[derive(Debug, Clone)]
pub struct FatArch {
    pub cputype: i32,
    pub cpusubtype: i32,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}

/// The parsed Mach-O file with all contents.
///
/// This is the main output of `parse_macho`. 32-bit sections/symbols
/// are promoted to 64-bit fields on read.
#[derive(Debug, Clone)]
pub struct MachOFile {
    pub header: MachHeader,
    pub commands: Vec<LoadCommand>,
    pub sections: Vec<Section>,
    pub symbols: Vec<NList>,
    pub strings: Vec<u8>,
}

impl MachOFile {
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

    /// Find a segment by name.
    pub fn segment(&self, name: &str) -> Option<&SegmentCommand> {
        self.segments().into_iter().find(|s| s.segname == name)
    }

    /// Find the first load command of a specific variant by matching function.
    pub fn find_dylib_command(&self, name: &str) -> Option<&DylibCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::LoadDylib(d) | LoadCommand::IdDylib(d) if d.name == name => Some(d),
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

    /// Find the dyld info command.
    pub fn dyld_info(&self) -> Option<&DyldInfoCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::DyldInfo(d) => Some(d),
            _ => None,
        })
    }

    /// Find the UUID command.
    pub fn uuid(&self) -> Option<&UuidCommand> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::Uuid(u) => Some(u),
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

    /// Return all dylib load commands (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB).
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

    /// Return the entry point (file offset) if LC_MAIN is present.
    pub fn entry_point(&self) -> Option<u64> {
        self.commands.iter().find_map(|c| match c {
            LoadCommand::Main(m) => Some(m.entryoff),
            _ => None,
        })
    }
}

/// Mach-O header (mach_header / mach_header_64).
#[derive(Debug, Clone)]
pub struct MachHeader {
    pub magic: u32,
    pub cputype: i32,
    pub cpusubtype: i32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl MachHeader {
    /// True if this is a 64-bit Mach-O.
    pub fn is_64bit(&self) -> bool {
        is_macho_64(self.magic)
    }

    /// True if this is little-endian.
    pub fn is_le(&self) -> bool {
        is_macho_le(self.magic)
    }

    /// Return 64 for 64-bit, 32 for 32-bit.
    pub fn bitness(&self) -> u8 {
        if self.is_64bit() {
            64
        } else {
            32
        }
    }
}

/// All known load commands.
#[derive(Debug, Clone)]
pub enum LoadCommand {
    Segment64(SegmentCommand),
    Symtab(SymtabCommand),
    Dysymtab(DysymtabCommand),
    Dylib(DylibCommand),
    LoadDylib(DylibCommand),
    IdDylib(DylibCommand),
    LoadWeakDylib(DylibCommand),
    ReexportDylib(DylibCommand),
    Dylinker(DylinkerCommand),
    Uuid(UuidCommand),
    VersionMin(VersionMinCommand),
    SourceVersion(SourceVersionCommand),
    Main(MainCommand),
    Rpath(RpathCommand),
    CodeSignature(LinkeditDataCommand),
    SegmentSplitInfo(LinkeditDataCommand),
    FunctionStarts(LinkeditDataCommand),
    DataInCode(LinkeditDataCommand),
    DyldInfo(DyldInfoCommand),
    DyldExportsTrie(LinkeditDataCommand),
    DyldChainedFixups(LinkeditDataCommand),
    BuildVersion(BuildVersionCommand),
    DyldEnvironment(DyldEnvironmentCommand),
    EncryptionInfo(EncryptionInfoCommand),
    EncryptionInfo64(EncryptionInfoCommand),
    LinkerOption(LinkerOptionCommand),
    FilesetEntry(FilesetEntryCommand),
    Note(NoteCommand),
    /// Any command we do not have a dedicated variant for.
    Unknown {
        cmd: u32,
        cmdsize: u32,
        data: Vec<u8>,
    },
}

/// Segment command (segment_command_64).
#[derive(Debug, Clone)]
pub struct SegmentCommand {
    pub segname: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: i32,
    pub initprot: i32,
    pub nsects: u32,
    pub flags: u32,
}

impl SegmentCommand {
    /// Check if this segment has read permission.
    pub fn is_readable(&self) -> bool {
        (self.initprot & VM_PROT_READ) != 0
    }

    /// Check if this segment has write permission.
    pub fn is_writable(&self) -> bool {
        (self.initprot & VM_PROT_WRITE) != 0
    }

    /// Check if this segment has execute permission.
    pub fn is_executable(&self) -> bool {
        (self.initprot & VM_PROT_EXECUTE) != 0
    }

    /// Check if this segment is Apple-protected.
    pub fn is_apple_protected(&self) -> bool {
        (self.flags & SG_PROTECTED_VERSION_1) != 0
    }
}

/// Section (section_64).
#[derive(Debug, Clone)]
pub struct Section {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

impl Section {
    /// Return the section type (low 8 bits of flags).
    pub fn section_type(&self) -> u32 {
        self.flags & SECTION_TYPE_MASK
    }

    /// Return the section attributes (upper 24 bits of flags).
    pub fn attributes(&self) -> u32 {
        self.flags & SECTION_ATTRIBUTES_MASK
    }

    /// True if this section contains pure instructions.
    pub fn is_pure_instructions(&self) -> bool {
        (self.flags & S_ATTR_PURE_INSTRUCTIONS) != 0
    }

    /// True if this section contains some instructions.
    pub fn is_some_instructions(&self) -> bool {
        (self.flags & S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    /// Returns an heuristic whether the section is executable.
    pub fn is_execute(&self) -> bool {
        if self.sectname == "__text" || self.segname == "__TEXT_EXEC" {
            return true;
        }
        self.is_pure_instructions() || self.is_some_instructions()
    }

    /// True if this is a zero-fill section.
    pub fn is_zerofill(&self) -> bool {
        self.section_type() == S_ZEROFILL
            || self.section_type() == S_GB_ZEROFILL
            || self.section_type() == S_THREAD_LOCAL_ZEROFILL
    }
}

/// NList entry (nlist_64).
///
/// For 32-bit files the n_value field is always promoted to u64.
#[derive(Debug, Clone)]
pub struct NList {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
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
    pub fn is_stab(&self) -> bool {
        (self.n_type & N_STAB) != 0
    }

    /// True if this is a private external symbol.
    pub fn is_private_external(&self) -> bool {
        (self.n_type & N_PEXT) != 0
    }

    /// True if this is an external (global) symbol.
    pub fn is_external(&self) -> bool {
        (self.n_type & N_EXT) != 0
    }

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

    /// Size of the NList entry in bytes (12 for 32-bit, 16 for 64-bit).
    pub fn entry_size(is_64bit: bool) -> usize {
        if is_64bit {
            16
        } else {
            12
        }
    }
}

/// Symtab command (symtab_command).
#[derive(Debug, Clone)]
pub struct SymtabCommand {
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

/// Dysymtab command (dysymtab_command).
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
    /// Return version as M.m.p string (x.y.z format from Mach-O packed version).
    pub fn version_string(version: u32) -> String {
        format!(
            "{}.{}.{}",
            version >> 16,
            (version >> 8) & 0xff,
            version & 0xff
        )
    }

    /// Current version as string.
    pub fn current_version_str(&self) -> String {
        Self::version_string(self.current_version)
    }

    /// Compatibility version as string.
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
    /// Return version as M.m.p string.
    pub fn version_string(&self) -> String {
        DylibCommand::version_string(self.version)
    }

    /// Return SDK version as M.m.p string.
    pub fn sdk_string(&self) -> String {
        DylibCommand::version_string(self.sdk)
    }
}

/// Source version command (source_version_command).
#[derive(Debug, Clone)]
pub struct SourceVersionCommand {
    /// Version packed as A.B.C.D.E (a:24, b:10, c:10, d:10, e:10).
    pub version: u64,
}

impl SourceVersionCommand {
    pub fn version_parts(&self) -> (u64, u64, u64, u64, u64) {
        let a = self.version >> 40;
        let b = (self.version >> 30) & 0x3ff;
        let c = (self.version >> 20) & 0x3ff;
        let d = (self.version >> 10) & 0x3ff;
        let e = self.version & 0x3ff;
        (a, b, c, d, e)
    }

    pub fn version_string(&self) -> String {
        let (a, b, c, d, e) = self.version_parts();
        format!("{}.{}.{}.{}.{}", a, b, c, d, e)
    }
}

/// Main command (entry_point_command, LC_MAIN).
#[derive(Debug, Clone)]
pub struct MainCommand {
    /// File offset of the entry point (__TEXT offset of main()).
    pub entryoff: u64,
    /// Initial stack size (if non-zero).
    pub stacksize: u64,
}

/// Rpath command (rpath_command).
#[derive(Debug, Clone)]
pub struct RpathCommand {
    pub path: String,
}

/// Linkedit data command (linkedit_data_command) - used for code signature,
/// segment split info, function starts, data-in-code, dyld exports trie,
/// dyld chained fixups.
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
    /// Return minos version as M.m.p string.
    pub fn minos_string(&self) -> String {
        DylibCommand::version_string(self.minos)
    }

    /// Return sdk version as M.m.p string.
    pub fn sdk_string(&self) -> String {
        DylibCommand::version_string(self.sdk)
    }
}

#[derive(Debug, Clone)]
pub struct BuildToolVersion {
    pub tool: u32,
    pub version: u32,
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
    /// Only present in 64-bit variant (pad field).
    pub is_64bit: bool,
}

/// Linker option command (linker_option_command, LC_LINKER_OPTIONS).
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

/// Relocation info.
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Export Trie Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct ExportTrie {
    pub entries: Vec<ExportEntry>,
}

#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub name: String,
    pub address: u64,
    pub flags: u64,
    pub other: u64,
    pub import_name: Option<String>,
}

impl ExportEntry {
    /// Check if this is a re-exported symbol.
    pub fn is_reexport(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0
    }

    /// Check if this is a weak definition.
    pub fn is_weak(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION) != 0
    }

    /// Check if this is a stub-and-resolver symbol.
    pub fn is_stub_and_resolver(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0
    }

    /// Return the export kind.
    pub fn kind(&self) -> u64 {
        self.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK
    }

    /// Return the export kind as a string.
    pub fn kind_name(&self) -> &'static str {
        match self.kind() {
            EXPORT_SYMBOL_FLAGS_KIND_REGULAR => "REGULAR",
            EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => "THREAD_LOCAL",
            EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => "ABSOLUTE",
            _ => "UNKNOWN",
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Binding / Rebase Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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

#[derive(Debug, Clone)]
pub struct ChainedFixups {
    pub starts_in_segment: Vec<u64>,
    pub imports: Vec<ChainedImport>,
}

#[derive(Debug, Clone)]
pub struct ChainedImport {
    pub name: String,
    pub dylib_ordinal: i32,
    pub weak: bool,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FAT / Universal Binary Parser
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Parse a FAT (universal) binary.
///
/// Returns `FatBinary` on success.
pub fn parse_fat(data: &[u8]) -> MachResult<FatBinary> {
    if data.len() < 8 {
        return Err(MachError::TruncatedData);
    }

    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let num_arches = u32::from_be_bytes(data[4..8].try_into().unwrap());

    if magic != FAT_MAGIC && magic != FAT_CIGAM {
        return Err(MachError::InvalidMagic(magic));
    }

    if num_arches == 0 || num_arches > 256 {
        return Err(MachError::InvalidHeader);
    }

    let arch_size = 20; // 5 x u32
    let total_size = 8 + num_arches as usize * arch_size;
    if data.len() < total_size {
        return Err(MachError::TruncatedData);
    }

    let mut arches = Vec::with_capacity(num_arches as usize);
    let is_be = magic == FAT_MAGIC;

    for i in 0..num_arches as usize {
        let off = 8 + i * arch_size;
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Mach-O Parser
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const MAX_LOAD_COMMANDS: u32 = 32_768;
const SEGNAME_LEN: usize = 16;

/// Parse a complete Mach-O file.
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

    // Read header fields
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

    let cputype = read_i32(4);
    let cpusubtype = read_i32(8);
    let filetype = read_u32(12);
    let ncmds = read_u32(16);
    let sizeofcmds = read_u32(20);
    let flags = read_u32(24);
    let reserved = if is_64 { read_u32(28) } else { 0 };

    let header = MachHeader {
        magic,
        cputype,
        cpusubtype,
        filetype,
        ncmds,
        sizeofcmds,
        flags,
        reserved,
    };

    if ncmds > MAX_LOAD_COMMANDS {
        return Err(MachError::TooManyCommands);
    }

    let cmd_start = header_size;
    let cmd_end = cmd_start + sizeofcmds as usize;
    if data.len() < cmd_end {
        return Err(MachError::TruncatedData);
    }

    // Parse load commands and collect sections
    let mut commands: Vec<LoadCommand> = Vec::with_capacity(ncmds as usize);
    let mut sections: Vec<Section> = Vec::new();
    let mut symbols: Vec<NList> = Vec::new();
    let mut strings: Vec<u8> = Vec::new();

    let mut offset = cmd_start;
    for _ in 0..ncmds {
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
            LC_SYMTAB => {
                parse_symtab_command(cmd_data, is_le, data, &mut symbols, &mut strings, is_64)
            }
            LC_DYSYMTAB => parse_dysymtab_command(cmd_data, is_le),
            LC_UUID => parse_uuid_command(cmd_data, is_le),
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => parse_dyld_info_command(cmd_data, is_le),
            LC_BUILD_VERSION => parse_build_version_command(cmd_data, is_le),
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS => parse_version_min_command(cmd_data, is_le),
            LC_SOURCE_VERSION => parse_source_version_command(cmd_data, is_le),
            LC_MAIN => parse_main_command(cmd_data, is_le),
            LC_DYLD_ENVIRONMENT => parse_dyld_environment_command(cmd_data, is_le),
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Individual Load Command Parsers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn read_le_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn read_be_u32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}

fn read_le_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

fn read_be_u64(data: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(data[off..off + 8].try_into().unwrap())
}

fn read_le_i32(data: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn read_be_i32(data: &[u8], off: usize) -> i32 {
    i32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}

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

    let maxprot = if is_le {
        read_le_i32(data, 56)
    } else {
        read_be_i32(data, 56)
    };
    let initprot = if is_le {
        read_le_i32(data, 60)
    } else {
        read_be_i32(data, 60)
    };
    let nsects = if is_le {
        read_le_u32(data, 64)
    } else {
        read_be_u32(data, 64)
    };
    let flags = if is_le {
        read_le_u32(data, 68)
    } else {
        read_be_u32(data, 68)
    };

    // Parse sections within the segment
    let section_size = 80; // section_64
    let sect_start = 72;

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

        let sect_offset = if is_le {
            read_le_u32(data, off + 48)
        } else {
            read_be_u32(data, off + 48)
        };
        let align = if is_le {
            read_le_u32(data, off + 52)
        } else {
            read_be_u32(data, off + 52)
        };
        let reloff = if is_le {
            read_le_u32(data, off + 56)
        } else {
            read_be_u32(data, off + 56)
        };
        let nreloc = if is_le {
            read_le_u32(data, off + 60)
        } else {
            read_be_u32(data, off + 60)
        };
        let sect_flags = if is_le {
            read_le_u32(data, off + 64)
        } else {
            read_be_u32(data, off + 64)
        };
        let reserved1 = if is_le {
            read_le_u32(data, off + 68)
        } else {
            read_be_u32(data, off + 68)
        };
        let reserved2 = if is_le {
            read_le_u32(data, off + 72)
        } else {
            read_be_u32(data, off + 72)
        };
        let reserved3 = if is_le {
            read_le_u32(data, off + 76)
        } else {
            read_be_u32(data, off + 76)
        };

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

fn parse_symtab_command(
    data: &[u8],
    is_le: bool,
    full_data: &[u8],
    symbols: &mut Vec<NList>,
    strings: &mut Vec<u8>,
    is_64: bool,
) -> LoadCommand {
    let symoff = if is_le {
        read_le_u32(data, 8)
    } else {
        read_be_u32(data, 8)
    };
    let nsyms = if is_le {
        read_le_u32(data, 12)
    } else {
        read_be_u32(data, 12)
    };
    let stroff = if is_le {
        read_le_u32(data, 16)
    } else {
        read_be_u32(data, 16)
    };
    let strsize = if is_le {
        read_le_u32(data, 20)
    } else {
        read_be_u32(data, 20)
    };

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

/// Look up a symbol's string from the string table.
pub fn symbol_name<'a>(nlist: &NList, strings: &'a [u8]) -> &'a str {
    if nlist.n_strx == 0 {
        return "";
    }
    let start = nlist.n_strx as usize;
    if start >= strings.len() {
        return "";
    }
    let end = strings[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(strings.len());
    std::str::from_utf8(&strings[start..end]).unwrap_or("")
}

fn parse_dysymtab_command(data: &[u8], is_le: bool) -> LoadCommand {
    let read_u = |off: usize| -> u32 {
        if is_le {
            read_le_u32(data, off)
        } else {
            read_be_u32(data, off)
        }
    };
    LoadCommand::Dysymtab(DysymtabCommand {
        ilocalsym: read_u(8),
        nlocalsym: read_u(12),
        iextdefsym: read_u(16),
        nextdefsym: read_u(20),
        iundefsym: read_u(24),
        nundefsym: read_u(28),
        tocoff: read_u(32),
        ntoc: read_u(36),
        modtaboff: read_u(40),
        nmodtab: read_u(44),
        extrefsymoff: read_u(48),
        nextrefsyms: read_u(52),
        indirectsymoff: read_u(56),
        nindirectsyms: read_u(60),
        extreloff: read_u(64),
        nextrel: read_u(68),
        locreloff: read_u(72),
        nlocrel: read_u(76),
    })
}

fn parse_dyld_info_command(data: &[u8], is_le: bool) -> LoadCommand {
    let read_u = |off: usize| -> u32 {
        if is_le {
            read_le_u32(data, off)
        } else {
            read_be_u32(data, off)
        }
    };
    LoadCommand::DyldInfo(DyldInfoCommand {
        rebase_off: read_u(8),
        rebase_size: read_u(12),
        bind_off: read_u(16),
        bind_size: read_u(20),
        weak_bind_off: read_u(24),
        weak_bind_size: read_u(28),
        lazy_bind_off: read_u(32),
        lazy_bind_size: read_u(36),
        export_off: read_u(40),
        export_size: read_u(44),
    })
}

fn parse_uuid_command(data: &[u8], _is_le: bool) -> LoadCommand {
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&data[8..24]);
    LoadCommand::Uuid(UuidCommand { uuid })
}

fn parse_build_version_command(data: &[u8], is_le: bool) -> LoadCommand {
    let platform = if is_le {
        read_le_u32(data, 8)
    } else {
        read_be_u32(data, 8)
    };
    let minos = if is_le {
        read_le_u32(data, 12)
    } else {
        read_be_u32(data, 12)
    };
    let sdk = if is_le {
        read_le_u32(data, 16)
    } else {
        read_be_u32(data, 16)
    };
    let ntools = if is_le {
        read_le_u32(data, 20)
    } else {
        read_be_u32(data, 20)
    };

    let mut tools = Vec::new();
    for i in 0..ntools as usize {
        let off = 24 + i * 8;
        if off + 8 > data.len() {
            break;
        }
        let tool = if is_le {
            read_le_u32(data, off)
        } else {
            read_be_u32(data, off)
        };
        let version = if is_le {
            read_le_u32(data, off + 4)
        } else {
            read_be_u32(data, off + 4)
        };
        tools.push(BuildToolVersion { tool, version });
    }

    LoadCommand::BuildVersion(BuildVersionCommand {
        platform,
        minos,
        sdk,
        ntools,
        tools,
    })
}

fn parse_version_min_command(data: &[u8], is_le: bool) -> LoadCommand {
    let version = if is_le {
        read_le_u32(data, 8)
    } else {
        read_be_u32(data, 8)
    };
    let sdk = if is_le {
        read_le_u32(data, 12)
    } else {
        read_be_u32(data, 12)
    };
    LoadCommand::VersionMin(VersionMinCommand { version, sdk })
}

fn parse_source_version_command(data: &[u8], is_le: bool) -> LoadCommand {
    let version = if is_le {
        read_le_u64(data, 8)
    } else {
        read_be_u64(data, 8)
    };
    LoadCommand::SourceVersion(SourceVersionCommand { version })
}

fn parse_main_command(data: &[u8], is_le: bool) -> LoadCommand {
    let entryoff = if is_le {
        read_le_u64(data, 8)
    } else {
        read_be_u64(data, 8)
    };
    let stacksize = if is_le {
        read_le_u64(data, 16)
    } else {
        read_be_u64(data, 16)
    };
    LoadCommand::Main(MainCommand {
        entryoff,
        stacksize,
    })
}

fn parse_dyld_environment_command(data: &[u8], _is_le: bool) -> LoadCommand {
    let value = read_padded_string(&data[8..], data.len() - 8);
    LoadCommand::DyldEnvironment(DyldEnvironmentCommand { value })
}

fn parse_dylib_command(
    data: &[u8],
    is_le: bool,
    mk: fn(DylibCommand) -> LoadCommand,
) -> LoadCommand {
    // dylib_command: cmd(4) + cmdsize(4) + name_offset(4) + timestamp(4) + current_version(4) + compat_version(4)
    // name_offset is the offset from the start of the command to the name string
    let name_offset = if is_le {
        read_le_u32(data, 8)
    } else {
        read_be_u32(data, 8)
    };
    let timestamp = if is_le {
        read_le_u32(data, 12)
    } else {
        read_be_u32(data, 12)
    };
    let current_version = if is_le {
        read_le_u32(data, 16)
    } else {
        read_be_u32(data, 16)
    };
    let compatibility_version = if is_le {
        read_le_u32(data, 20)
    } else {
        read_be_u32(data, 20)
    };

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

fn parse_dylinker_command(data: &[u8], is_le: bool) -> LoadCommand {
    let name_offset = if is_le {
        read_le_u32(data, 8)
    } else {
        read_be_u32(data, 8)
    };
    let name_start = name_offset as usize;
    let name = if name_start < data.len() {
        read_padded_string(&data[name_start..], data.len() - name_start)
    } else {
        String::new()
    };
    LoadCommand::Dylinker(DylinkerCommand { name })
}

fn parse_rpath_command(data: &[u8], is_le: bool) -> LoadCommand {
    let path_offset = if is_le {
        read_le_u32(data, 8)
    } else {
        read_be_u32(data, 8)
    };
    let path_start = path_offset as usize;
    let path = if path_start < data.len() {
        read_padded_string(&data[path_start..], data.len() - path_start)
    } else {
        String::new()
    };
    LoadCommand::Rpath(RpathCommand { path })
}

fn parse_linkedit_data_command(
    data: &[u8],
    is_le: bool,
    mk: fn(LinkeditDataCommand) -> LoadCommand,
) -> LoadCommand {
    let dataoff = if is_le {
        read_le_u32(data, 8)
    } else {
        read_be_u32(data, 8)
    };
    let datasize = if is_le {
        read_le_u32(data, 12)
    } else {
        read_be_u32(data, 12)
    };
    mk(LinkeditDataCommand { dataoff, datasize })
}

fn parse_encryption_info_command(data: &[u8], is_le: bool, is_64bit: bool) -> LoadCommand {
    let cryptoff = if is_le {
        read_le_u32(data, 8)
    } else {
        read_be_u32(data, 8)
    };
    let cryptsize = if is_le {
        read_le_u32(data, 12)
    } else {
        read_be_u32(data, 12)
    };
    let cryptid = if is_le {
        read_le_u32(data, 16)
    } else {
        read_be_u32(data, 16)
    };

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

fn parse_linker_option_command(data: &[u8], is_le: bool) -> LoadCommand {
    let count = if is_le {
        read_le_u32(data, 8)
    } else {
        read_be_u32(data, 8)
    };
    let mut options = Vec::new();
    // Linker options are null-terminated strings packed sequentially after the count field
    let strings_data = &data[12..];
    let mut pos = 0usize;
    for _ in 0..count as usize {
        if pos >= strings_data.len() {
            break;
        }
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

fn parse_fileset_entry_command(data: &[u8], is_le: bool) -> LoadCommand {
    let vmaddr = if is_le {
        read_le_u64(data, 8)
    } else {
        read_be_u64(data, 8)
    };
    let fileoff = if is_le {
        read_le_u64(data, 16)
    } else {
        read_be_u64(data, 16)
    };
    let entry_id_offset = if is_le {
        read_le_u32(data, 24)
    } else {
        read_be_u32(data, 24)
    };
    let entry_start = entry_id_offset as usize;
    let entry_id = if entry_start < data.len() {
        read_padded_string(&data[entry_start..], data.len() - entry_start)
    } else {
        String::new()
    };
    LoadCommand::FilesetEntry(FilesetEntryCommand {
        vmaddr,
        fileoff,
        entry_id,
    })
}

fn parse_note_command(data: &[u8], is_le: bool) -> LoadCommand {
    let data_owner = read_padded_string(&data[8..24], SEGNAME_LEN);
    let offset = if is_le {
        read_le_u64(data, 24)
    } else {
        read_be_u64(data, 24)
    };
    let size = if is_le {
        read_le_u64(data, 32)
    } else {
        read_be_u64(data, 32)
    };
    LoadCommand::Note(NoteCommand {
        data_owner,
        offset,
        size,
    })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Export Trie Parser
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Parse the export trie from raw bytes.
///
/// `data` should point to the start of the export trie.
/// `base` is the file offset where the trie data starts (used for relative addressing).
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
            // Terminal node: read flags and address
            if pos >= data.len() {
                return Err(MachError::InvalidExportTrie);
            }
            let (flags, flags_len) = decode_uleb128(&data[pos..])?;
            pos += flags_len;

            let (address, other, import_name) = if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0 {
                let (other_val, o_len) = decode_uleb128(&data[pos..])?;
                pos += o_len;
                // Read import name (null-terminated string)
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

        // The terminal_size ULEB tells how many bytes the terminal information takes.
        // Children follow immediately after. `pos` has been advanced past the terminal info
        // by the parsing above, so use it directly.
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
            if child_pos >= data.len() {
                break;
            }
            // Read child edge label (null-terminated string)
            let label_end = data[child_pos..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.len() - child_pos);
            let child_label =
                String::from_utf8_lossy(&data[child_pos..child_pos + label_end]).to_string();
            child_pos += label_end + 1;

            if child_pos >= data.len() {
                break;
            }
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

    // Start parsing at node offset 0
    parse_node(data, 0, "", 0, &mut entries, &mut visited)?;

    // Sort entries by name for deterministic output
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ExportTrie { entries })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DYLD Opcode-Based Binding Parser
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Parse DYLD binding opcodes from compressed bind data.
///
/// This handles both normal bind and lazy bind opcodes.
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

    let pointer_size: u64 = 8; // Assume 64-bit

    while pos < data.len() {
        let byte = data[pos];
        pos += 1;
        let opcode = byte & BIND_OPCODE_MASK;
        let imm = byte & BIND_IMMEDIATE_MASK;

        match opcode {
            BIND_OPCODE_DONE => {
                // Flush any accumulated entries
                if !symbol_name.is_empty() && count > 0 {
                    for i in 0..count {
                        let addr = if seg_index < segment_base_addresses.len() as u8 {
                            segment_base_addresses[seg_index as usize]
                                + seg_offset
                                + i * pointer_size
                        } else {
                            seg_offset + i * pointer_size
                        };
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
                if !is_lazy {
                    // For non-lazy, BIND_OPCODE_DONE means we are really done
                    return Ok(BindingInfo { entries });
                }
                // Reset state for next library
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
                // Flush any previous symbol's entries
                if !symbol_name.is_empty() && count > 0 {
                    for i in 0..count {
                        let addr = if seg_index < segment_base_addresses.len() as u8 {
                            segment_base_addresses[seg_index as usize]
                                + seg_offset
                                + i * pointer_size
                        } else {
                            seg_offset + i * pointer_size
                        };
                        entries.push(BindEntry {
                            name: symbol_name.clone(),
                            address: addr,
                            bind_type,
                            addend,
                            dylib_ordinal,
                            flags: symbol_flags,
                        });
                    }
                    count = 0;
                }
                symbol_flags = imm;
                // Read null-terminated symbol name
                let name_end = data[pos..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(data.len() - pos);
                symbol_name = String::from_utf8_lossy(&data[pos..pos + name_end]).to_string();
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
                // Add one entry at current address
                if !symbol_name.is_empty() {
                    let addr = if seg_index < segment_base_addresses.len() as u8 {
                        segment_base_addresses[seg_index as usize] + seg_offset
                    } else {
                        seg_offset
                    };
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
                count = 0;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                // Add one entry, then advance address by ULEB
                if !symbol_name.is_empty() {
                    let addr = if seg_index < segment_base_addresses.len() as u8 {
                        segment_base_addresses[seg_index as usize] + seg_offset
                    } else {
                        seg_offset
                    };
                    entries.push(BindEntry {
                        name: symbol_name.clone(),
                        address: addr,
                        bind_type,
                        addend,
                        dylib_ordinal,
                        flags: symbol_flags,
                    });
                }
                let (val, len) = decode_uleb128(&data[pos..])?;
                pos += len;
                seg_offset += val + pointer_size;
                count = 0;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                // Add one entry, then advance address by imm * pointer_size + pointer_size
                if !symbol_name.is_empty() {
                    let addr = if seg_index < segment_base_addresses.len() as u8 {
                        segment_base_addresses[seg_index as usize] + seg_offset
                    } else {
                        seg_offset
                    };
                    entries.push(BindEntry {
                        name: symbol_name.clone(),
                        address: addr,
                        bind_type,
                        addend,
                        dylib_ordinal,
                        flags: symbol_flags,
                    });
                }
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
                        let addr = if seg_index < segment_base_addresses.len() as u8 {
                            segment_base_addresses[seg_index as usize]
                                + seg_offset
                                + i * (pointer_size + skp)
                        } else {
                            seg_offset + i * (pointer_size + skp)
                        };
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
                // Threaded bind sub-opcode
                let sub = imm;
                match sub {
                    BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB => {
                        let (_val, len) = decode_uleb128(&data[pos..])?;
                        pos += len;
                    }
                    BIND_SUBOPCODE_THREADED_APPLY => {
                        // Apply threaded bind - create one entry
                        if !symbol_name.is_empty() {
                            let addr = if seg_index < segment_base_addresses.len() as u8 {
                                segment_base_addresses[seg_index as usize] + seg_offset
                            } else {
                                seg_offset
                            };
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

/// Convenience function to parse export trie from a Mach-O file's dyld info.
pub fn parse_macho_export_trie(data: &[u8], macho: &MachOFile) -> MachResult<ExportTrie> {
    if let Some(dyld_info) = macho.dyld_info() {
        if dyld_info.export_off > 0 && dyld_info.export_size > 0 {
            let start = dyld_info.export_off as usize;
            let end = start + dyld_info.export_size as usize;
            if end <= data.len() {
                return parse_export_trie(&data[start..end]);
            }
        }
    }

    // Also try DyldExportsTrie load command
    for cmd in &macho.commands {
        if let LoadCommand::DyldExportsTrie(lc) = cmd {
            if lc.dataoff > 0 && lc.datasize > 0 {
                let start = lc.dataoff as usize;
                let end = start + lc.datasize as usize;
                if end <= data.len() {
                    return parse_export_trie(&data[start..end]);
                }
            }
        }
    }

    Ok(ExportTrie { entries: vec![] })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_constants() {
        assert!(is_macho_magic(MH_MAGIC_64));
        assert!(is_macho_magic(MH_CIGAM_64));
        assert!(is_macho_magic(MH_MAGIC));
        assert!(is_macho_magic(MH_CIGAM));
        assert!(!is_macho_magic(0xdeadbeef));

        assert!(is_macho_64(MH_MAGIC_64));
        assert!(is_macho_64(MH_CIGAM_64));
        assert!(!is_macho_64(MH_MAGIC));
        assert!(!is_macho_64(MH_CIGAM));

        assert!(is_macho_le(MH_CIGAM));
        assert!(is_macho_le(MH_CIGAM_64));
        assert!(!is_macho_le(MH_MAGIC));
        assert!(!is_macho_le(MH_MAGIC_64));
    }

    #[test]
    fn test_cpu_type_constants() {
        assert_eq!(CPU_TYPE_POWERPC64, CPU_TYPE_POWERPC | CPU_ARCH_ABI64);
        assert_eq!(CPU_TYPE_X86_64, CPU_TYPE_X86 | CPU_ARCH_ABI64);
        assert_eq!(CPU_TYPE_ARM64, CPU_TYPE_ARM | CPU_ARCH_ABI64);
        assert_eq!(cpu_type_bitness(CPU_TYPE_ARM64), 64);
        assert_eq!(cpu_type_bitness(CPU_TYPE_X86), 32);
        assert_eq!(cpu_type_bitness(CPU_TYPE_X86_64), 64);
    }

    #[test]
    fn test_fat_binary() {
        // Build a minimal FAT binary with one arch
        let mut data = Vec::new();
        data.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes()); // 1 arch
                                                     // arch entry: cputype, cpusubtype, offset, size, align
        data.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
        data.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_be_bytes());
        data.extend_from_slice(&0x1000u32.to_be_bytes());
        data.extend_from_slice(&0x10000u32.to_be_bytes());
        data.extend_from_slice(&14u32.to_be_bytes()); // 2^14 alignment

        let fat = parse_fat(&data).expect("Should parse FAT binary");
        assert_eq!(fat.arches.len(), 1);
        assert_eq!(fat.arches[0].cputype, CPU_TYPE_ARM64);
        assert_eq!(fat.arches[0].cpusubtype, CPU_SUBTYPE_ARM64_ALL);
        assert_eq!(fat.arches[0].offset, 0x1000);
        assert_eq!(fat.arches[0].size, 0x10000);
    }

    #[test]
    fn test_fat_binary_cigam() {
        let mut data = Vec::new();
        data.extend_from_slice(&FAT_CIGAM.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes()); // 2 arches
                                                     // First arch
        data.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        data.extend_from_slice(&CPU_SUBTYPE_X86_ALL.to_le_bytes());
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x5000u32.to_le_bytes());
        data.extend_from_slice(&12u32.to_le_bytes());
        // Second arch
        data.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        data.extend_from_slice(&CPU_SUBTYPE_ARM64E.to_le_bytes());
        data.extend_from_slice(&0x6000u32.to_le_bytes());
        data.extend_from_slice(&0x8000u32.to_le_bytes());
        data.extend_from_slice(&14u32.to_le_bytes());

        let fat = parse_fat(&data).expect("Should parse FAT binary (CIGAM)");
        assert_eq!(fat.arches.len(), 2);
        assert_eq!(fat.arches[0].cputype, CPU_TYPE_X86_64);
        assert_eq!(fat.arches[1].cputype, CPU_TYPE_ARM64);
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
    fn test_uleb128_decode() {
        assert_eq!(decode_uleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_uleb128(&[0x01]).unwrap(), (1, 1));
        assert_eq!(decode_uleb128(&[0x7f]).unwrap(), (127, 1));
        assert_eq!(decode_uleb128(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(decode_uleb128(&[0xe5, 0x8e, 0x26]).unwrap(), (624485, 3));
    }

    #[test]
    fn test_sleb128_decode() {
        assert_eq!(decode_sleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_sleb128(&[0x01]).unwrap(), (1, 1));
        assert_eq!(decode_sleb128(&[0x7f]).unwrap(), (-1, 1));
        assert_eq!(decode_sleb128(&[0x80, 0x01]).unwrap(), (128, 2));
    }

    #[test]
    fn test_export_trie_parsing() {
        // A minimal export trie with one entry
        // Node at offset 0:
        //   terminal_size = 10 (let's assume 7 bytes for the uleb128 "10" encoding boundary)
        //   flags = 0
        //   address = 0x1000
        //   children_count = 0
        // Let's build it manually.
        //
        // terminal_size uleb: the terminal info is:
        //   flags uleb = 0 (1 byte)
        //   address uleb = 0x1000 => 0x80 0x20 (2 bytes)
        //   so terminal_size = 3
        //
        // Full node:
        //   uleb(3) = 0x03
        //   uleb(0) = 0x00  (flags)
        //   uleb(0x1000) = 0x80 0x20  (address)
        //   uleb(0) = 0x00  (children count)
        let trie_data = [0x03u8, 0x00, 0x80, 0x20, 0x00];
        let trie = parse_export_trie(&trie_data).expect("Should parse");
        // Note: the name will be empty since it's the root node
        assert!(!trie.entries.is_empty());
        let entry = &trie.entries[0];
        assert_eq!(entry.address, 0x1000);
        assert_eq!(entry.flags, 0);
    }

    #[test]
    fn test_empty_export_trie() {
        let trie = parse_export_trie(&[]).expect("Should handle empty data");
        assert!(trie.entries.is_empty());
    }

    #[test]
    fn test_file_type_names() {
        assert_eq!(file_type_name(MH_OBJECT), "OBJECT");
        assert_eq!(file_type_name(MH_EXECUTE), "EXECUTE");
        assert_eq!(file_type_name(MH_DYLIB), "DYLIB");
        assert_eq!(file_type_name(MH_BUNDLE), "BUNDLE");
    }

    #[test]
    fn test_load_command_names() {
        assert_eq!(load_command_name(LC_SEGMENT_64), "LC_SEGMENT_64");
        assert_eq!(load_command_name(LC_SYMTAB), "LC_SYMTAB");
        assert_eq!(load_command_name(LC_MAIN), "LC_MAIN");
        assert_eq!(load_command_name(LC_BUILD_VERSION), "LC_BUILD_VERSION");
    }

    #[test]
    fn test_version_string() {
        assert_eq!(DylibCommand::version_string(0x000d0000), "13.0.0");
        assert_eq!(DylibCommand::version_string(0x000e0003), "14.0.3");
    }

    #[test]
    fn test_header_flag_names() {
        let flags = MH_PIE | MH_NO_HEAP_EXECUTION;
        let names = header_flag_names(flags);
        assert!(names.contains(&"PIE"));
        assert!(names.contains(&"NO_HEAP_EXECUTION"));
    }

    #[test]
    fn test_symbol_name() {
        let strings = b"__mh_execute_header\0_main\0";
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
    }
}
