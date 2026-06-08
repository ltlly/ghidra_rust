//! Mach-O header file types and flags ported from Ghidra's
//! `ghidra.app.util.bin.format.macho.MachHeaderFileTypes` and
//! `ghidra.app.util.bin.format.macho.MachHeaderFlags`.
//!
//! References:
//! - <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>

// ---------------------------------------------------------------------------
// File types
// ---------------------------------------------------------------------------

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
/// Companion file with only debug sections.
pub const MH_DSYM: u32 = 0xA;
/// x86_64 kexts.
pub const MH_KEXT_BUNDLE: u32 = 0xB;
/// Kernel cache fileset.
pub const MH_FILESET: u32 = 0xC;

/// Returns the short name of the Mach-O file type (e.g. "EXECUTE", "DYLIB").
pub fn file_type_name(file_type: u32) -> &'static str {
    match file_type {
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
        _ => "Unknown",
    }
}

/// Returns a human-readable description of the Mach-O file type.
pub fn file_type_description(file_type: u32) -> &'static str {
    match file_type {
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
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Header flags
// ---------------------------------------------------------------------------

/// The object file has no undefined references.
pub const MH_NOUNDEFS: u32 = 0x1;
/// The object file is the output of an incremental link against a base file.
pub const MH_INCRLINK: u32 = 0x2;
/// The object file is input for the dynamic linker.
pub const MH_DYLDLINK: u32 = 0x4;
/// The object file's undefined references are bound by the dynamic linker when loaded.
pub const MH_BINDATLOAD: u32 = 0x8;
/// The file has its dynamic undefined references prebound.
pub const MH_PREBOUND: u32 = 0x10;
/// The file has its read-only and read-write segments split.
pub const MH_SPLIT_SEGS: u32 = 0x20;
/// The shared library init routine is to be run lazily (obsolete).
pub const MH_LAZY_INIT: u32 = 0x40;
/// The image is using two-level name space bindings.
pub const MH_TWOLEVEL: u32 = 0x80;
/// The executable is forcing all images to use flat name space bindings.
pub const MH_FORCE_FLAT: u32 = 0x100;
/// This umbrella guarantees no multiple definitions of symbols in its sub-images.
pub const MH_NOMULTIDEFS: u32 = 0x200;
/// Do not have dyld notify the prebinding agent about this executable.
pub const MH_NOFIXPREBINDING: u32 = 0x400;
/// The binary is not prebound but can have its prebinding redone.
pub const MH_PREBINDABLE: u32 = 0x800;
/// Binds to all two-level namespace modules of its dependent libraries.
pub const MH_ALLMODSBOUND: u32 = 0x1000;
/// Safe to divide up the sections into sub-sections via symbols for dead code stripping.
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
/// The binary has been canonicalized via the unprebind operation.
pub const MH_CANONICAL: u32 = 0x4000;
/// The final linked image contains external weak symbols.
pub const MH_WEAK_DEFINES: u32 = 0x8000;
/// The final linked image uses weak symbols.
pub const MH_BINDS_TO_WEAK: u32 = 0x1_0000;
/// All stacks in the task will be given stack execution privilege.
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x2_0000;
/// The binary declares it is safe for use in processes with uid zero.
pub const MH_ROOT_SAFE: u32 = 0x4_0000;
/// The binary declares it is safe for use in processes when issetugid() is true.
pub const MH_SETUID_SAFE: u32 = 0x8_0000;
/// The static linker does not need to examine dependent dylibs for re-exports.
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x10_0000;
/// The OS will load the main executable at a random address (PIE).
pub const MH_PIE: u32 = 0x20_0000;
/// Only for dylibs. The static linker will not create a LC_LOAD_DYLIB if no symbols referenced.
pub const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x40_0000;
/// Contains a section of type S_THREAD_LOCAL_VARIABLES.
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x80_0000;
/// The OS will run the main executable with a non-executable heap.
pub const MH_NO_HEAP_EXECUTION: u32 = 0x100_0000;
/// The code was linked for use in an application extension.
pub const MH_APP_EXTENSION_SAFE: u32 = 0x200_0000;
/// External symbols do not include all symbols listed in dyld info.
pub const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO: u32 = 0x0400_0000;
/// Allow LC_MIN_VERSION_MACOS and LC_BUILD_VERSION load commands.
pub const MH_SIM_SUPPORT: u32 = 0x0800_0000;
/// The dylib is part of the dyld shared cache.
pub const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;

/// Returns a list of flag names that are set in the given flags value.
///
/// Each name is returned without the `MH_` prefix (e.g. "NOUNDEFS", "PIE").
pub fn get_flag_names(flags: u32) -> Vec<&'static str> {
    const FLAG_TABLE: &[(u32, &str)] = &[
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
    FLAG_TABLE
        .iter()
        .filter(|(bit, _)| (flags & bit) != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_name() {
        assert_eq!(file_type_name(MH_EXECUTE), "EXECUTE");
        assert_eq!(file_type_name(MH_DYLIB), "DYLIB");
        assert_eq!(file_type_name(MH_CORE), "CORE");
        assert_eq!(file_type_name(0xFF), "Unknown");
    }

    #[test]
    fn test_file_type_description() {
        assert_eq!(
            file_type_description(MH_EXECUTE),
            "Demand Paged Executable File"
        );
        assert_eq!(
            file_type_description(MH_DYLIB),
            "Dynamically Bound Shared Library"
        );
    }

    #[test]
    fn test_flag_names_empty() {
        assert!(get_flag_names(0).is_empty());
    }

    #[test]
    fn test_flag_names_single() {
        let flags = get_flag_names(MH_PIE);
        assert_eq!(flags, vec!["PIE"]);
    }

    #[test]
    fn test_flag_names_multiple() {
        let flags = get_flag_names(MH_NOUNDEFS | MH_DYLDLINK | MH_PIE);
        assert!(flags.contains(&"NOUNDEFS"));
        assert!(flags.contains(&"DYLDLINK"));
        assert!(flags.contains(&"PIE"));
        assert_eq!(flags.len(), 3);
    }

    #[test]
    fn test_all_file_types_covered() {
        for ft in MH_OBJECT..=MH_FILESET {
            assert_ne!(file_type_name(ft), "Unknown", "file_type=0x{:x}", ft);
        }
    }
}
