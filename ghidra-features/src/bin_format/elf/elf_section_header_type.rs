//! ELF section header type registry ported from Ghidra's `ElfSectionHeaderType.java`.
//!
//! Provides:
//! - [`ElfSectionHeaderType`] -- a named section header type with its numeric value
//!   and description
//! - Default section header type instances (SHT_NULL through SHT_SYMTAB_SHNDX)
//! - OS-specific, GNU-specific, and Sun-specific section header types
//! - A registry for looking up section header types by value
//! - Helper functions for type classification

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use super::elf_section_header_constants;

// ---------------------------------------------------------------------------
// ElfSectionHeaderType
// ---------------------------------------------------------------------------

/// A named ELF section header type.
///
/// Each instance pairs a numeric `value` (the `sh_type` constant), a `name`
/// (e.g. `"SHT_PROGBITS"`), and a human-readable `description`.
#[derive(Debug, Clone)]
pub struct ElfSectionHeaderType {
    /// The numeric section header type value (e.g. `1` for SHT_PROGBITS).
    pub value: u32,
    /// The symbolic name (e.g. `"SHT_PROGBITS"`).
    pub name: &'static str,
    /// A human-readable description.
    pub description: &'static str,
}

impl ElfSectionHeaderType {
    /// Create a new section header type entry.
    pub const fn new(value: u32, name: &'static str, description: &'static str) -> Self {
        Self {
            value,
            name,
            description,
        }
    }
}

impl fmt::Display for ElfSectionHeaderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(0x{:08x})", self.name, self.value)
    }
}

// ---------------------------------------------------------------------------
// Standard Section Header Types (SHT_*)
// ---------------------------------------------------------------------------

/// Inactive section header.
pub const SHT_NULL_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_NULL,
    "SHT_NULL",
    "Inactive section header",
);
/// Program defined section.
pub const SHT_PROGBITS_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_PROGBITS,
    "SHT_PROGBITS",
    "Program defined section",
);
/// Symbol table for link editing and dynamic linking.
pub const SHT_SYMTAB_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_SYMTAB,
    "SHT_SYMTAB",
    "Symbol table for link editing and dynamic linking",
);
/// String table.
pub const SHT_STRTAB_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_STRTAB,
    "SHT_STRTAB",
    "String table",
);
/// Relocation entries with explicit addends.
pub const SHT_RELA_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_RELA,
    "SHT_RELA",
    "Relocation entries with explicit addends",
);
/// Symbol hash table for dynamic linking.
pub const SHT_HASH_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_HASH,
    "SHT_HASH",
    "Symbol hash table for dynamic linking",
);
/// Dynamic linking information.
pub const SHT_DYNAMIC_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_DYNAMIC,
    "SHT_DYNAMIC",
    "Dynamic linking information",
);
/// Section holds information that marks the file.
pub const SHT_NOTE_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_NOTE,
    "SHT_NOTE",
    "Section holds information that marks the file",
);
/// Section contains no bytes.
pub const SHT_NOBITS_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_NOBITS,
    "SHT_NOBITS",
    "Section contains no bytes",
);
/// Relocation entries without explicit addends.
pub const SHT_REL_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_REL,
    "SHT_REL",
    "Relocation entries w/o explicit addends",
);
/// Undefined.
pub const SHT_SHLIB_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_SHLIB,
    "SHT_SHLIB",
    "",
);
/// Symbol table for dynamic linking.
pub const SHT_DYNSYM_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_DYNSYM,
    "SHT_DYNSYM",
    "Symbol table for dynamic linking",
);
/// Array of initializer functions.
pub const SHT_INIT_ARRAY_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_INIT_ARRAY,
    "SHT_INIT_ARRAY",
    "Array of initializer functions",
);
/// Array of finalizer functions.
pub const SHT_FINI_ARRAY_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_FINI_ARRAY,
    "SHT_FINI_ARRAY",
    "Array of finalizer functions",
);
/// Array of pre-initializer functions.
pub const SHT_PREINIT_ARRAY_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_PREINIT_ARRAY,
    "SHT_PREINIT_ARRAY",
    "Array of pre-initializer functions",
);
/// Section group.
pub const SHT_GROUP_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_GROUP,
    "SHT_GROUP",
    "Section group",
);
/// Extended section indices.
pub const SHT_SYMTAB_SHNDX_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_SYMTAB_SHNDX,
    "SHT_SYMTAB_SHNDX",
    "Extended section indices",
);

// ---------------------------------------------------------------------------
// OS-Specific Section Header Types
// ---------------------------------------------------------------------------

/// Android relocation entries without explicit addends.
pub const SHT_ANDROID_REL_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_ANDROID_REL,
    "SHT_ANDROID_REL",
    "Android relocation entries w/o explicit addends",
);
/// Android relocation entries with explicit addends.
pub const SHT_ANDROID_RELA_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_ANDROID_RELA,
    "SHT_ANDROID_RELA",
    "Android relocation entries with explicit addends",
);

// ---------------------------------------------------------------------------
// GNU-Specific Section Header Types
// ---------------------------------------------------------------------------

/// Object attributes.
pub const SHT_GNU_ATTRIBUTES_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_GNU_ATTRIBUTES,
    "SHT_GNU_ATTRIBUTES",
    "Object attributes",
);
/// GNU-style hash table.
pub const SHT_GNU_HASH_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_GNU_HASH,
    "SHT_GNU_HASH",
    "GNU-style hash table",
);
/// Prelink library list.
pub const SHT_GNU_LIBLIST_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_GNU_LIBLIST,
    "SHT_GNU_LIBLIST",
    "Prelink library list",
);
/// Checksum for DSO content.
pub const SHT_CHECKSUM_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_CHECKSUM,
    "SHT_CHECKSUM",
    "Checksum for DSO content",
);

// ---------------------------------------------------------------------------
// Sun-Specific Section Header Types
// ---------------------------------------------------------------------------

/// Sun move section.
pub const SHT_SUNW_MOVE_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_SUNW_MOVE,
    "SHT_SUNW_move",
    "",
);
/// Sun COMDAT section.
pub const SHT_SUNW_COMDAT_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_SUNW_COMDAT,
    "SHT_SUNW_COMDAT",
    "",
);
/// Sun syminfo section.
pub const SHT_SUNW_SYMINFO_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_SUNW_SYMINFO,
    "SHT_SUNW_syminfo",
    "",
);

// ---------------------------------------------------------------------------
// GNU Version Section Header Types
// ---------------------------------------------------------------------------

/// Version definition section.
pub const SHT_GNU_VERDEF_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_GNU_VERDEF,
    "SHT_GNU_verdef",
    "Version definition section",
);
/// Version needs section.
pub const SHT_GNU_VERNEED_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_GNU_VERNEED,
    "SHT_GNU_verneed",
    "Version needs section",
);
/// Version symbol table.
pub const SHT_GNU_VERSYM_TYPE: ElfSectionHeaderType = ElfSectionHeaderType::new(
    elf_section_header_constants::SHT_GNU_VERSYM,
    "SHT_GNU_versym",
    "Version symbol table",
);

// ---------------------------------------------------------------------------
// Registry / Lookup
// ---------------------------------------------------------------------------

/// Build the default section header type registry (all standard SHT_* types).
fn build_default_section_header_types() -> HashMap<u32, &'static ElfSectionHeaderType> {
    let mut map = HashMap::new();
    let types: &[&ElfSectionHeaderType] = &[
        // Standard types
        &SHT_NULL_TYPE,
        &SHT_PROGBITS_TYPE,
        &SHT_SYMTAB_TYPE,
        &SHT_STRTAB_TYPE,
        &SHT_RELA_TYPE,
        &SHT_HASH_TYPE,
        &SHT_DYNAMIC_TYPE,
        &SHT_NOTE_TYPE,
        &SHT_NOBITS_TYPE,
        &SHT_REL_TYPE,
        &SHT_SHLIB_TYPE,
        &SHT_DYNSYM_TYPE,
        &SHT_INIT_ARRAY_TYPE,
        &SHT_FINI_ARRAY_TYPE,
        &SHT_PREINIT_ARRAY_TYPE,
        &SHT_GROUP_TYPE,
        &SHT_SYMTAB_SHNDX_TYPE,
        // OS-specific
        &SHT_ANDROID_REL_TYPE,
        &SHT_ANDROID_RELA_TYPE,
        // GNU-specific
        &SHT_GNU_ATTRIBUTES_TYPE,
        &SHT_GNU_HASH_TYPE,
        &SHT_GNU_LIBLIST_TYPE,
        &SHT_CHECKSUM_TYPE,
        // Sun-specific
        &SHT_SUNW_MOVE_TYPE,
        &SHT_SUNW_COMDAT_TYPE,
        &SHT_SUNW_SYMINFO_TYPE,
        // GNU version
        &SHT_GNU_VERDEF_TYPE,
        &SHT_GNU_VERNEED_TYPE,
        &SHT_GNU_VERSYM_TYPE,
    ];
    for t in types {
        map.insert(t.value, *t);
    }
    map
}

/// Look up a section header type by its numeric value.
///
/// Returns a reference to the [`ElfSectionHeaderType`] if the value is a known
/// section header type, or `None` for unknown/processor-specific types
/// not in the default registry.
pub fn lookup_section_header_type(value: u32) -> Option<&'static ElfSectionHeaderType> {
    static REGISTRY: OnceLock<HashMap<u32, &'static ElfSectionHeaderType>> = OnceLock::new();
    let map = REGISTRY.get_or_init(build_default_section_header_types);
    map.get(&value).copied()
}

/// Returns a human-readable name for the given section header type value.
///
/// For known types returns the SHT_* name; for unknown values returns `"SHT_UNKNOWN"`.
pub fn section_header_type_name(value: u32) -> &'static str {
    lookup_section_header_type(value)
        .map(|t| t.name)
        .unwrap_or("SHT_UNKNOWN")
}

/// Returns `true` if the given section header type is in the OS-specific range
/// (0x60000000 - 0x6fffffff).
pub fn is_os_specific_section_type(sh_type: u32) -> bool {
    sh_type >= 0x60000000 && sh_type <= 0x6fffffff
}

/// Returns `true` if the given section header type is in the processor-specific range
/// (0x70000000 - 0x7fffffff).
pub fn is_processor_specific_section_type(sh_type: u32) -> bool {
    sh_type >= 0x70000000 && sh_type <= 0x7fffffff
}

/// Returns `true` if the given section header type represents a string table.
pub fn is_string_table_type(sh_type: u32) -> bool {
    sh_type == elf_section_header_constants::SHT_STRTAB
}

/// Returns `true` if the given section header type represents a symbol table.
pub fn is_symbol_table_type(sh_type: u32) -> bool {
    sh_type == elf_section_header_constants::SHT_SYMTAB
        || sh_type == elf_section_header_constants::SHT_DYNSYM
}

/// Returns `true` if the given section header type represents a relocation table.
pub fn is_relocation_type(sh_type: u32) -> bool {
    sh_type == elf_section_header_constants::SHT_REL
        || sh_type == elf_section_header_constants::SHT_RELA
        || sh_type == elf_section_header_constants::SHT_RELR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_section_header_types() {
        assert_eq!(SHT_NULL_TYPE.value, 0);
        assert_eq!(SHT_PROGBITS_TYPE.value, 1);
        assert_eq!(SHT_SYMTAB_TYPE.value, 2);
        assert_eq!(SHT_STRTAB_TYPE.value, 3);
        assert_eq!(SHT_RELA_TYPE.value, 4);
        assert_eq!(SHT_HASH_TYPE.value, 5);
        assert_eq!(SHT_DYNAMIC_TYPE.value, 6);
        assert_eq!(SHT_NOTE_TYPE.value, 7);
        assert_eq!(SHT_NOBITS_TYPE.value, 8);
        assert_eq!(SHT_REL_TYPE.value, 9);
        assert_eq!(SHT_SHLIB_TYPE.value, 10);
        assert_eq!(SHT_DYNSYM_TYPE.value, 11);
    }

    #[test]
    fn test_section_header_type_display() {
        let s = format!("{}", SHT_PROGBITS_TYPE);
        assert!(s.contains("SHT_PROGBITS"));
        assert!(s.contains("0x00000001"));
    }

    #[test]
    fn test_lookup_section_header_type() {
        let t = lookup_section_header_type(1);
        assert!(t.is_some());
        assert_eq!(t.unwrap().name, "SHT_PROGBITS");
        assert_eq!(t.unwrap().description, "Program defined section");
    }

    #[test]
    fn test_lookup_unknown() {
        assert!(lookup_section_header_type(9999).is_none());
    }

    #[test]
    fn test_section_header_type_name_fn() {
        assert_eq!(section_header_type_name(0), "SHT_NULL");
        assert_eq!(section_header_type_name(1), "SHT_PROGBITS");
        assert_eq!(section_header_type_name(2), "SHT_SYMTAB");
        assert_eq!(section_header_type_name(0x6ffffff6), "SHT_GNU_HASH");
        assert_eq!(section_header_type_name(9999), "SHT_UNKNOWN");
    }

    #[test]
    fn test_is_os_specific_section_type() {
        assert!(is_os_specific_section_type(0x60000001)); // SHT_ANDROID_REL
        assert!(is_os_specific_section_type(0x6ffffff6)); // SHT_GNU_HASH
        assert!(!is_os_specific_section_type(1)); // SHT_PROGBITS
        assert!(!is_os_specific_section_type(0x70000000));
    }

    #[test]
    fn test_is_processor_specific_section_type() {
        assert!(is_processor_specific_section_type(0x70000000));
        assert!(is_processor_specific_section_type(0x7fffffff));
        assert!(!is_processor_specific_section_type(1));
        assert!(!is_processor_specific_section_type(0x60000000));
    }

    #[test]
    fn test_is_string_table_type() {
        assert!(is_string_table_type(elf_section_header_constants::SHT_STRTAB));
        assert!(!is_string_table_type(elf_section_header_constants::SHT_SYMTAB));
    }

    #[test]
    fn test_is_symbol_table_type() {
        assert!(is_symbol_table_type(elf_section_header_constants::SHT_SYMTAB));
        assert!(is_symbol_table_type(elf_section_header_constants::SHT_DYNSYM));
        assert!(!is_symbol_table_type(elf_section_header_constants::SHT_STRTAB));
    }

    #[test]
    fn test_is_relocation_type() {
        assert!(is_relocation_type(elf_section_header_constants::SHT_REL));
        assert!(is_relocation_type(elf_section_header_constants::SHT_RELA));
        assert!(is_relocation_type(elf_section_header_constants::SHT_RELR));
        assert!(!is_relocation_type(elf_section_header_constants::SHT_PROGBITS));
    }

    #[test]
    fn test_init_array_types() {
        assert_eq!(SHT_INIT_ARRAY_TYPE.value, 14);
        assert_eq!(SHT_FINI_ARRAY_TYPE.value, 15);
        assert_eq!(SHT_PREINIT_ARRAY_TYPE.value, 16);
    }

    #[test]
    fn test_gnu_version_types() {
        assert_eq!(SHT_GNU_VERDEF_TYPE.value, 0x6ffffffd);
        assert_eq!(SHT_GNU_VERNEED_TYPE.value, 0x6ffffffe);
        assert_eq!(SHT_GNU_VERSYM_TYPE.value, 0x6fffffff);
    }

    #[test]
    fn test_sun_types() {
        assert_eq!(SHT_SUNW_MOVE_TYPE.value, 0x6ffffffa);
        assert_eq!(SHT_SUNW_COMDAT_TYPE.value, 0x6ffffffb);
        assert_eq!(SHT_SUNW_SYMINFO_TYPE.value, 0x6ffffffc);
    }

    #[test]
    fn test_android_types() {
        assert_eq!(SHT_ANDROID_REL_TYPE.value, 0x60000001);
        assert_eq!(SHT_ANDROID_RELA_TYPE.value, 0x60000002);
    }
}
