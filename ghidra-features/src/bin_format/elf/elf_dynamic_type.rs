//! ELF dynamic entry types ported from Ghidra's `ElfDynamicType.java`.
//!
//! Provides:
//! - [`ElfDynamicValueType`] -- classification of dynamic entry value semantics
//! - [`ElfDynamicType`] -- a named dynamic entry type with its numeric value
//!   and description
//! - Constants for all standard DT_* values, GNU extensions, Android extensions,
//!   and DF_* / DF_1_* flag values
//! - A registry function for looking up dynamic types by value

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Value Type Classification
// ---------------------------------------------------------------------------

/// The semantic type of a dynamic entry's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfDynamicValueType {
    /// A plain integer value.
    VALUE,
    /// A virtual address.
    ADDRESS,
    /// An index into the string table.
    STRING,
}

// ---------------------------------------------------------------------------
// ElfDynamicType
// ---------------------------------------------------------------------------

/// A named ELF dynamic entry type.
///
/// Each instance pairs a numeric `value` (the `d_tag` constant), a `name`
/// (e.g. `"DT_NEEDED"`), a human-readable `description`, and a
/// [`ElfDynamicValueType`] indicating the semantic interpretation.
#[derive(Debug, Clone)]
pub struct ElfDynamicType {
    /// The numeric tag value (e.g. `1` for DT_NEEDED).
    pub value: u32,
    /// The symbolic name (e.g. `"DT_NEEDED"`).
    pub name: &'static str,
    /// A human-readable description.
    pub description: &'static str,
    /// How the value field should be interpreted.
    pub value_type: ElfDynamicValueType,
}

impl ElfDynamicType {
    /// Create a new dynamic type entry.
    pub const fn new(
        value: u32,
        name: &'static str,
        description: &'static str,
        value_type: ElfDynamicValueType,
    ) -> Self {
        Self {
            value,
            name,
            description,
            value_type,
        }
    }
}

impl fmt::Display for ElfDynamicType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(0x{:08x})", self.name, self.value)
    }
}

// ---------------------------------------------------------------------------
// Standard Dynamic Entry Types (DT_*)
// ---------------------------------------------------------------------------

/// Marks end of dynamic section.
pub const DT_NULL: ElfDynamicType =
    ElfDynamicType::new(0, "DT_NULL", "Marks end of dynamic section", ElfDynamicValueType::VALUE);
/// Name of needed library.
pub const DT_NEEDED: ElfDynamicType =
    ElfDynamicType::new(1, "DT_NEEDED", "Name of needed library", ElfDynamicValueType::STRING);
/// Size in bytes of PLT relocs.
pub const DT_PLTRELSZ: ElfDynamicType =
    ElfDynamicType::new(2, "DT_PLTRELSZ", "Size in bytes of PLT relocs", ElfDynamicValueType::VALUE);
/// Processor defined value.
pub const DT_PLTGOT: ElfDynamicType =
    ElfDynamicType::new(3, "DT_PLTGOT", "Processor defined value", ElfDynamicValueType::ADDRESS);
/// Address of symbol hash table.
pub const DT_HASH: ElfDynamicType =
    ElfDynamicType::new(4, "DT_HASH", "Address of symbol hash table", ElfDynamicValueType::ADDRESS);
/// Address of string table.
pub const DT_STRTAB: ElfDynamicType =
    ElfDynamicType::new(5, "DT_STRTAB", "Address of string table", ElfDynamicValueType::ADDRESS);
/// Address of symbol table.
pub const DT_SYMTAB: ElfDynamicType =
    ElfDynamicType::new(6, "DT_SYMTAB", "Address of symbol table", ElfDynamicValueType::ADDRESS);
/// Address of Rela relocs.
pub const DT_RELA: ElfDynamicType =
    ElfDynamicType::new(7, "DT_RELA", "Address of Rela relocs", ElfDynamicValueType::ADDRESS);
/// Total size of Rela relocs.
pub const DT_RELASZ: ElfDynamicType =
    ElfDynamicType::new(8, "DT_RELASZ", "Total size of Rela relocs", ElfDynamicValueType::VALUE);
/// Size of one Rela reloc.
pub const DT_RELAENT: ElfDynamicType =
    ElfDynamicType::new(9, "DT_RELAENT", "Size of one Rela reloc", ElfDynamicValueType::VALUE);
/// Size of string table.
pub const DT_STRSZ: ElfDynamicType =
    ElfDynamicType::new(10, "DT_STRSZ", "Size of string table", ElfDynamicValueType::VALUE);
/// Size of one symbol table entry.
pub const DT_SYMENT: ElfDynamicType =
    ElfDynamicType::new(11, "DT_SYMENT", "Size of one symbol table entry", ElfDynamicValueType::VALUE);
/// Address of init function.
pub const DT_INIT: ElfDynamicType =
    ElfDynamicType::new(12, "DT_INIT", "Address of init function", ElfDynamicValueType::ADDRESS);
/// Address of termination function.
pub const DT_FINI: ElfDynamicType =
    ElfDynamicType::new(13, "DT_FINI", "Address of termination function", ElfDynamicValueType::ADDRESS);
/// Name of shared object (string ref).
pub const DT_SONAME: ElfDynamicType =
    ElfDynamicType::new(14, "DT_SONAME", "Name of shared object (string ref)", ElfDynamicValueType::STRING);
/// Library search path.
pub const DT_RPATH: ElfDynamicType =
    ElfDynamicType::new(15, "DT_RPATH", "Library search path", ElfDynamicValueType::STRING);
/// Start symbol search here.
pub const DT_SYMBOLIC: ElfDynamicType =
    ElfDynamicType::new(16, "DT_SYMBOLIC", "Start symbol search here", ElfDynamicValueType::VALUE);
/// Address of Rel relocs.
pub const DT_REL: ElfDynamicType =
    ElfDynamicType::new(17, "DT_REL", "Address of Rel relocs", ElfDynamicValueType::ADDRESS);
/// Total size of Rel relocs.
pub const DT_RELSZ: ElfDynamicType =
    ElfDynamicType::new(18, "DT_RELSZ", "Total size of Rel relocs", ElfDynamicValueType::VALUE);
/// Size of one Rel reloc.
pub const DT_RELENT: ElfDynamicType =
    ElfDynamicType::new(19, "DT_RELENT", "Size of one Rel reloc", ElfDynamicValueType::VALUE);
/// Type of reloc in PLT.
pub const DT_PLTREL: ElfDynamicType =
    ElfDynamicType::new(20, "DT_PLTREL", "Type of reloc in PLT", ElfDynamicValueType::VALUE);
/// For debugging (unspecified).
pub const DT_DEBUG: ElfDynamicType =
    ElfDynamicType::new(21, "DT_DEBUG", "For debugging (unspecified)", ElfDynamicValueType::VALUE);
/// Reloc might modify .text.
pub const DT_TEXTREL: ElfDynamicType =
    ElfDynamicType::new(22, "DT_TEXTREL", "Reloc might modify .text", ElfDynamicValueType::VALUE);
/// Address of PLT relocs.
pub const DT_JMPREL: ElfDynamicType =
    ElfDynamicType::new(23, "DT_JMPREL", "Address of PLT relocs", ElfDynamicValueType::ADDRESS);
/// Process relocations of object.
pub const DT_BIND_NOW: ElfDynamicType =
    ElfDynamicType::new(24, "DT_BIND_NOW", "Process relocations of object", ElfDynamicValueType::VALUE);
/// Address of array with addresses of init functions.
pub const DT_INIT_ARRAY: ElfDynamicType =
    ElfDynamicType::new(25, "DT_INIT_ARRAY", "Address of array with addresses of init fct", ElfDynamicValueType::ADDRESS);
/// Address of array with addresses of fini functions.
pub const DT_FINI_ARRAY: ElfDynamicType =
    ElfDynamicType::new(26, "DT_FINI_ARRAY", "Address of array with addresses of fini fct", ElfDynamicValueType::ADDRESS);
/// Size in bytes of DT_INIT_ARRAY.
pub const DT_INIT_ARRAYSZ: ElfDynamicType =
    ElfDynamicType::new(27, "DT_INIT_ARRAYSZ", "Size in bytes of DT_INIT_ARRAY", ElfDynamicValueType::VALUE);
/// Size in bytes of DT_FINI_ARRAY.
pub const DT_FINI_ARRAYSZ: ElfDynamicType =
    ElfDynamicType::new(28, "DT_FINI_ARRAYSZ", "Size in bytes of DT_FINI_ARRAY", ElfDynamicValueType::VALUE);
/// Library search path (string ref).
pub const DT_RUNPATH: ElfDynamicType =
    ElfDynamicType::new(29, "DT_RUNPATH", "Library search path (string ref)", ElfDynamicValueType::STRING);
/// Flags for the object being loaded.
pub const DT_FLAGS: ElfDynamicType =
    ElfDynamicType::new(30, "DT_FLAGS", "Flags for the object being loaded", ElfDynamicValueType::VALUE);
/// Array with addresses of preinit functions.
pub const DT_PREINIT_ARRAY: ElfDynamicType =
    ElfDynamicType::new(32, "DT_PREINIT_ARRAY", "Array with addresses of preinit fct", ElfDynamicValueType::ADDRESS);
/// Size in bytes of DT_PREINIT_ARRAY.
pub const DT_PREINIT_ARRAYSZ: ElfDynamicType =
    ElfDynamicType::new(33, "DT_PREINIT_ARRAYSZ", "Size in bytes of DT_PREINIT_ARRAY", ElfDynamicValueType::VALUE);

// ---------------------------------------------------------------------------
// RELR Relocation Support
// ---------------------------------------------------------------------------

/// Total size of Relr relocs.
pub const DT_RELRSZ: ElfDynamicType =
    ElfDynamicType::new(35, "DT_RELRSZ", "Total size of Relr relocs", ElfDynamicValueType::VALUE);
/// Address of Relr relocs.
pub const DT_RELR: ElfDynamicType =
    ElfDynamicType::new(36, "DT_RELR", "Address of Relr relocs", ElfDynamicValueType::ADDRESS);
/// Size of Relr relocation entry.
pub const DT_RELRENT: ElfDynamicType =
    ElfDynamicType::new(37, "DT_RELRENT", "Size of Relr relocation entry", ElfDynamicValueType::VALUE);

// ---------------------------------------------------------------------------
// Android-Specific Dynamic Entry Types
// ---------------------------------------------------------------------------

/// Address of Android Rel relocs.
pub const DT_ANDROID_REL: ElfDynamicType =
    ElfDynamicType::new(0x6000000F, "DT_ANDROID_REL", "Address of Rel relocs", ElfDynamicValueType::ADDRESS);
/// Total size of Android Rel relocs.
pub const DT_ANDROID_RELSZ: ElfDynamicType =
    ElfDynamicType::new(0x60000010, "DT_ANDROID_RELSZ", "Total size of Rel relocs", ElfDynamicValueType::VALUE);
/// Address of Android Rela relocs.
pub const DT_ANDROID_RELA: ElfDynamicType =
    ElfDynamicType::new(0x60000011, "DT_ANDROID_RELA", "Address of Rela relocs", ElfDynamicValueType::ADDRESS);
/// Total size of Android Rela relocs.
pub const DT_ANDROID_RELASZ: ElfDynamicType =
    ElfDynamicType::new(0x60000012, "DT_ANDROID_RELASZ", "Total size of Rela relocs", ElfDynamicValueType::VALUE);
/// Address of Android Relr relocs.
pub const DT_ANDROID_RELR: ElfDynamicType =
    ElfDynamicType::new(0x6FFFE000, "DT_ANDROID_RELR", "Address of Relr relocs", ElfDynamicValueType::ADDRESS);
/// Total size of Android Relr relocs.
pub const DT_ANDROID_RELRSZ: ElfDynamicType =
    ElfDynamicType::new(0x6FFFE001, "DT_ANDROID_RELRSZ", "Total size of Relr relocs", ElfDynamicValueType::VALUE);
/// Size of Android Relr relocation entry.
pub const DT_ANDROID_RELRENT: ElfDynamicType =
    ElfDynamicType::new(0x6FFFE003, "DT_ANDROID_RELRENT", "Size of Relr relocation entry", ElfDynamicValueType::VALUE);

// ---------------------------------------------------------------------------
// GNU-Specific Dynamic Entry Types
// ---------------------------------------------------------------------------

/// Prelinking timestamp.
pub const DT_GNU_PRELINKED: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdf5, "DT_GNU_PRELINKED", "Prelinking timestamp", ElfDynamicValueType::VALUE);
/// Size of conflict section.
pub const DT_GNU_CONFLICTSZ: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdf6, "DT_GNU_CONFLICTSZ", "Size of conflict section", ElfDynamicValueType::VALUE);
/// Size of library list.
pub const DT_GNU_LIBLISTSZ: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdf7, "DT_GNU_LIBLISTSZ", "Size of library list", ElfDynamicValueType::VALUE);
/// Checksum.
pub const DT_CHECKSUM: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdf8, "DT_CHECKSUM", "", ElfDynamicValueType::VALUE);
/// PLT padding.
pub const DT_PLTPADSZ: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdf9, "DT_PLTPADSZ", "", ElfDynamicValueType::VALUE);
/// Move entry size.
pub const DT_MOVEENT: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdfa, "DT_MOVEENT", "", ElfDynamicValueType::VALUE);
/// Move table size.
pub const DT_MOVESZ: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdfb, "DT_MOVESZ", "", ElfDynamicValueType::VALUE);
/// Feature flags.
pub const DT_FEATURE_1: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdfc, "DT_FEATURE_1", "", ElfDynamicValueType::VALUE);
/// Position flags.
pub const DT_POSFLAG_1: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdfd, "DT_POSFLAG_1", "", ElfDynamicValueType::VALUE);
/// Symbol info size.
pub const DT_SYMINSZ: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdfe, "DT_SYMINSZ", "", ElfDynamicValueType::VALUE);
/// Symbol info entry size.
pub const DT_SYMINENT: ElfDynamicType =
    ElfDynamicType::new(0x6ffffdff, "DT_SYMINENT", "", ElfDynamicValueType::VALUE);

/// GNU-style extended hash table.
pub const DT_GNU_XHASH: ElfDynamicType =
    ElfDynamicType::new(0x6ffffef4, "DT_GNU_XHASH", "GNU-style extended hash table", ElfDynamicValueType::ADDRESS);
/// GNU-style hash table.
pub const DT_GNU_HASH: ElfDynamicType =
    ElfDynamicType::new(0x6ffffef5, "DT_GNU_HASH", "GNU-style hash table", ElfDynamicValueType::ADDRESS);
/// TLS descriptor PLT.
pub const DT_TLSDESC_PLT: ElfDynamicType =
    ElfDynamicType::new(0x6ffffef6, "DT_TLSDESC_PLT", "", ElfDynamicValueType::VALUE);
/// TLS descriptor GOT.
pub const DT_TLSDESC_GOT: ElfDynamicType =
    ElfDynamicType::new(0x6ffffef7, "DT_TLSDESC_GOT", "", ElfDynamicValueType::VALUE);
/// Start of conflict section.
pub const DT_GNU_CONFLICT: ElfDynamicType =
    ElfDynamicType::new(0x6ffffef8, "DT_GNU_CONFLICT", "Start of conflict section", ElfDynamicValueType::ADDRESS);
/// Library list.
pub const DT_GNU_LIBLIST: ElfDynamicType =
    ElfDynamicType::new(0x6ffffef9, "DT_GNU_LIBLIST", "Library list", ElfDynamicValueType::VALUE);
/// Configuration information.
pub const DT_CONFIG: ElfDynamicType =
    ElfDynamicType::new(0x6ffffefa, "DT_CONFIG", "Configuration information", ElfDynamicValueType::VALUE);
/// Dependency auditing.
pub const DT_DEPAUDIT: ElfDynamicType =
    ElfDynamicType::new(0x6ffffefb, "DT_DEPAUDIT", "Dependency auditing", ElfDynamicValueType::VALUE);
/// Object auditing.
pub const DT_AUDIT: ElfDynamicType =
    ElfDynamicType::new(0x6ffffefc, "DT_AUDIT", "Object auditing", ElfDynamicValueType::VALUE);
/// PLT padding.
pub const DT_PLTPAD: ElfDynamicType =
    ElfDynamicType::new(0x6ffffefd, "DT_PLTPAD", "PLT padding", ElfDynamicValueType::VALUE);
/// Move table.
pub const DT_MOVETAB: ElfDynamicType =
    ElfDynamicType::new(0x6ffffefe, "DT_MOVETAB", "Move table", ElfDynamicValueType::ADDRESS);
/// Syminfo table.
pub const DT_SYMINFO: ElfDynamicType =
    ElfDynamicType::new(0x6ffffeff, "DT_SYMINFO", "Syminfo table", ElfDynamicValueType::ADDRESS);

// ---------------------------------------------------------------------------
// Version-Related Dynamic Entry Types
// ---------------------------------------------------------------------------

/// Address of symbol version table.
pub const DT_VERSYM: ElfDynamicType =
    ElfDynamicType::new(0x6ffffff0, "DT_VERSYM", "Address of symbol version table", ElfDynamicValueType::ADDRESS);
/// Number of Rela relocations.
pub const DT_RELACOUNT: ElfDynamicType =
    ElfDynamicType::new(0x6ffffff9, "DT_RELACOUNT", "", ElfDynamicValueType::VALUE);
/// Number of Rel relocations.
pub const DT_RELCOUNT: ElfDynamicType =
    ElfDynamicType::new(0x6ffffffa, "DT_RELCOUNT", "", ElfDynamicValueType::VALUE);
/// State flags.
pub const DT_FLAGS_1: ElfDynamicType =
    ElfDynamicType::new(0x6ffffffb, "DT_FLAGS_1", "State flags", ElfDynamicValueType::VALUE);
/// Address of version definition table.
pub const DT_VERDEF: ElfDynamicType =
    ElfDynamicType::new(0x6ffffffc, "DT_VERDEF", "Address of version definition table", ElfDynamicValueType::ADDRESS);
/// Number of version definitions.
pub const DT_VERDEFNUM: ElfDynamicType =
    ElfDynamicType::new(0x6ffffffd, "DT_VERDEFNUM", "Number of version definitions", ElfDynamicValueType::VALUE);
/// Address of table with needed versions.
pub const DT_VERNEED: ElfDynamicType =
    ElfDynamicType::new(0x6ffffffe, "DT_VERNEED", "Address of table with needed versions", ElfDynamicValueType::ADDRESS);
/// Number of needed versions.
pub const DT_VERNEEDNUM: ElfDynamicType =
    ElfDynamicType::new(0x6fffffff, "DT_VERNEEDNUM", "Number of needed versions", ElfDynamicValueType::VALUE);

// ---------------------------------------------------------------------------
// Processor-Specific Dynamic Entry Types
// ---------------------------------------------------------------------------

/// Shared object to load before self.
pub const DT_AUXILIARY: ElfDynamicType =
    ElfDynamicType::new(0x7ffffffd, "DT_AUXILIARY", "Shared object to load before self", ElfDynamicValueType::VALUE);
/// Shared object to get values from.
pub const DT_FILTER: ElfDynamicType =
    ElfDynamicType::new(0x7fffffff, "DT_FILTER", "Shared object to get values from", ElfDynamicValueType::VALUE);

// ---------------------------------------------------------------------------
// DT_FLAGS Values
// ---------------------------------------------------------------------------

/// `$ORIGIN` processing required.
pub const DF_ORIGIN: u32 = 0x1;
/// Symbolic symbol resolution required.
pub const DF_SYMBOLIC: u32 = 0x2;
/// Text relocations exist.
pub const DF_TEXTREL: u32 = 0x4;
/// Non-lazy binding required.
pub const DF_BIND_NOW: u32 = 0x8;
/// Object uses static TLS scheme.
pub const DF_STATIC_TLS: u32 = 0x10;

// ---------------------------------------------------------------------------
// DT_FLAGS_1 Values
// ---------------------------------------------------------------------------

/// Set RTLD_NOW for this object.
pub const DF_1_NOW: u32 = 0x1;
/// Set RTLD_GLOBAL for this object.
pub const DF_1_GLOBAL: u32 = 0x2;
/// Group of objects.
pub const DF_1_GROUP: u32 = 0x4;
/// Set RTLD_NODELETE for this object.
pub const DF_1_NODELETE: u32 = 0x8;
/// Trigger filtee loading at runtime.
pub const DF_1_LOADFLTR: u32 = 0x10;
/// Initialize object first at runtime.
pub const DF_1_INITFIRST: u32 = 0x20;
/// Do not open file at runtime.
pub const DF_1_NOOPEN: u32 = 0x40;
/// Set $ORIGIN for this object.
pub const DF_1_ORIGIN: u32 = 0x80;
/// Direct binding enabled.
pub const DF_1_DIRECT: u32 = 0x100;
/// Ignore interposers.
pub const DF_1_INTERPOSE: u32 = 0x400;
/// Do not search default library path.
pub const DF_1_NODEFLIB: u32 = 0x800;

// ---------------------------------------------------------------------------
// Registry / Lookup
// ---------------------------------------------------------------------------

/// Build the default dynamic type registry (all standard DT_* types).
fn build_default_dynamic_types() -> HashMap<u32, &'static ElfDynamicType> {
    let mut map = HashMap::new();
    // Standard types
    let types: &[&ElfDynamicType] = &[
        &DT_NULL, &DT_NEEDED, &DT_PLTRELSZ, &DT_PLTGOT, &DT_HASH, &DT_STRTAB,
        &DT_SYMTAB, &DT_RELA, &DT_RELASZ, &DT_RELAENT, &DT_STRSZ, &DT_SYMENT,
        &DT_INIT, &DT_FINI, &DT_SONAME, &DT_RPATH, &DT_SYMBOLIC, &DT_REL,
        &DT_RELSZ, &DT_RELENT, &DT_PLTREL, &DT_DEBUG, &DT_TEXTREL, &DT_JMPREL,
        &DT_BIND_NOW, &DT_INIT_ARRAY, &DT_FINI_ARRAY, &DT_INIT_ARRAYSZ,
        &DT_FINI_ARRAYSZ, &DT_RUNPATH, &DT_FLAGS, &DT_PREINIT_ARRAY,
        &DT_PREINIT_ARRAYSZ, &DT_RELRSZ, &DT_RELR, &DT_RELRENT,
        // Android
        &DT_ANDROID_REL, &DT_ANDROID_RELSZ, &DT_ANDROID_RELA, &DT_ANDROID_RELASZ,
        &DT_ANDROID_RELR, &DT_ANDROID_RELRSZ, &DT_ANDROID_RELRENT,
        // GNU
        &DT_GNU_PRELINKED, &DT_GNU_CONFLICTSZ, &DT_GNU_LIBLISTSZ, &DT_CHECKSUM,
        &DT_PLTPADSZ, &DT_MOVEENT, &DT_MOVESZ, &DT_FEATURE_1, &DT_POSFLAG_1,
        &DT_SYMINSZ, &DT_SYMINENT, &DT_GNU_XHASH, &DT_GNU_HASH,
        &DT_TLSDESC_PLT, &DT_TLSDESC_GOT, &DT_GNU_CONFLICT, &DT_GNU_LIBLIST,
        &DT_CONFIG, &DT_DEPAUDIT, &DT_AUDIT, &DT_PLTPAD, &DT_MOVETAB,
        &DT_SYMINFO,
        // Version
        &DT_VERSYM, &DT_RELACOUNT, &DT_RELCOUNT, &DT_FLAGS_1, &DT_VERDEF,
        &DT_VERDEFNUM, &DT_VERNEED, &DT_VERNEEDNUM,
        // Processor-specific
        &DT_AUXILIARY, &DT_FILTER,
    ];
    for t in types {
        map.insert(t.value, *t);
    }
    map
}

/// Look up a dynamic type by its numeric value.
///
/// Returns a reference to the [`ElfDynamicType`] if the value is a known
/// standard dynamic tag, or `None` for unknown/processor-specific tags
/// not in the default registry.
pub fn lookup_dynamic_type(value: u32) -> Option<&'static ElfDynamicType> {
    static REGISTRY: OnceLock<HashMap<u32, &'static ElfDynamicType>> = OnceLock::new();
    let map = REGISTRY.get_or_init(build_default_dynamic_types);
    map.get(&value).copied()
}

/// Returns a human-readable name for the given dynamic tag value.
///
/// For known tags returns the DT_* name; for unknown values returns `"DT_UNKNOWN"`.
pub fn dynamic_tag_name(tag: u32) -> &'static str {
    lookup_dynamic_type(tag)
        .map(|dt| dt.name)
        .unwrap_or("DT_UNKNOWN")
}

/// Returns `true` if the given dynamic tag value points to a string table entry.
pub fn is_string_dynamic_tag(tag: u32) -> bool {
    matches!(tag, 1 | 14 | 15 | 29) // DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH
}

/// Returns `true` if the given dynamic tag value points to an address.
pub fn is_address_dynamic_tag(tag: u32) -> bool {
    matches!(
        tag,
        3 | 5 | 6 | 7 | 12 | 13 | 17 | 23 | 25 | 26
    ) // DT_PLTGOT, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_INIT, DT_FINI, DT_REL, DT_JMPREL, DT_INIT_ARRAY, DT_FINI_ARRAY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_dynamic_types() {
        assert_eq!(DT_NULL.value, 0);
        assert_eq!(DT_NEEDED.value, 1);
        assert_eq!(DT_STRTAB.value, 5);
        assert_eq!(DT_SYMTAB.value, 6);
        assert_eq!(DT_HASH.value, 4);
        assert_eq!(DT_INIT.value, 12);
        assert_eq!(DT_FINI.value, 13);
    }

    #[test]
    fn test_dynamic_type_display() {
        let s = format!("{}", DT_NEEDED);
        assert!(s.contains("DT_NEEDED"));
        assert!(s.contains("0x00000001"));
    }

    #[test]
    fn test_lookup_dynamic_type() {
        let dt = lookup_dynamic_type(1);
        assert!(dt.is_some());
        assert_eq!(dt.unwrap().name, "DT_NEEDED");
        assert_eq!(dt.unwrap().value_type, ElfDynamicValueType::STRING);
    }

    #[test]
    fn test_lookup_unknown() {
        assert!(lookup_dynamic_type(9999).is_none());
    }

    #[test]
    fn test_dynamic_tag_name() {
        assert_eq!(dynamic_tag_name(0), "DT_NULL");
        assert_eq!(dynamic_tag_name(1), "DT_NEEDED");
        assert_eq!(dynamic_tag_name(5), "DT_STRTAB");
        assert_eq!(dynamic_tag_name(0x6ffffef5), "DT_GNU_HASH");
        assert_eq!(dynamic_tag_name(9999), "DT_UNKNOWN");
    }

    #[test]
    fn test_is_string_dynamic_tag() {
        assert!(is_string_dynamic_tag(1)); // DT_NEEDED
        assert!(is_string_dynamic_tag(14)); // DT_SONAME
        assert!(is_string_dynamic_tag(15)); // DT_RPATH
        assert!(is_string_dynamic_tag(29)); // DT_RUNPATH
        assert!(!is_string_dynamic_tag(3)); // DT_PLTGOT
        assert!(!is_string_dynamic_tag(5)); // DT_STRTAB
    }

    #[test]
    fn test_is_address_dynamic_tag() {
        assert!(is_address_dynamic_tag(3)); // DT_PLTGOT
        assert!(is_address_dynamic_tag(5)); // DT_STRTAB
        assert!(is_address_dynamic_tag(6)); // DT_SYMTAB
        assert!(is_address_dynamic_tag(12)); // DT_INIT
        assert!(is_address_dynamic_tag(13)); // DT_FINI
        assert!(!is_address_dynamic_tag(1)); // DT_NEEDED
        assert!(!is_address_dynamic_tag(2)); // DT_PLTRELSZ
    }

    #[test]
    fn test_relr_types() {
        assert_eq!(DT_RELRSZ.value, 35);
        assert_eq!(DT_RELR.value, 36);
        assert_eq!(DT_RELRENT.value, 37);
    }

    #[test]
    fn test_android_types() {
        assert_eq!(DT_ANDROID_REL.value, 0x6000000F);
        assert_eq!(DT_ANDROID_RELSZ.value, 0x60000010);
        assert_eq!(DT_ANDROID_RELA.value, 0x60000011);
        assert_eq!(DT_ANDROID_RELASZ.value, 0x60000012);
    }

    #[test]
    fn test_gnu_hash() {
        assert_eq!(DT_GNU_HASH.value, 0x6ffffef5);
        assert_eq!(DT_GNU_XHASH.value, 0x6ffffef4);
    }

    #[test]
    fn test_df_flags() {
        assert_eq!(DF_ORIGIN, 0x1);
        assert_eq!(DF_SYMBOLIC, 0x2);
        assert_eq!(DF_TEXTREL, 0x4);
        assert_eq!(DF_BIND_NOW, 0x8);
    }

    #[test]
    fn test_df_1_flags() {
        assert_eq!(DF_1_NOW, 0x1);
        assert_eq!(DF_1_GLOBAL, 0x2);
        assert_eq!(DF_1_GROUP, 0x4);
        assert_eq!(DF_1_NODELETE, 0x8);
        assert_eq!(DF_1_NODEFLIB, 0x800);
    }

    #[test]
    fn test_value_types() {
        assert_eq!(DT_NULL.value_type, ElfDynamicValueType::VALUE);
        assert_eq!(DT_NEEDED.value_type, ElfDynamicValueType::STRING);
        assert_eq!(DT_STRTAB.value_type, ElfDynamicValueType::ADDRESS);
        assert_eq!(DT_HASH.value_type, ElfDynamicValueType::ADDRESS);
        assert_eq!(DT_PLTGOT.value_type, ElfDynamicValueType::ADDRESS);
    }

    #[test]
    fn test_version_types() {
        assert_eq!(DT_VERSYM.value, 0x6ffffff0);
        assert_eq!(DT_VERDEF.value, 0x6ffffffc);
        assert_eq!(DT_VERNEED.value, 0x6ffffffe);
        assert_eq!(DT_VERNEEDNUM.value, 0x6fffffff);
    }

    #[test]
    fn test_processor_specific() {
        assert_eq!(DT_AUXILIARY.value, 0x7ffffffd);
        assert_eq!(DT_FILTER.value, 0x7fffffff);
    }
}
