//! ELF section header constants ported from Ghidra's `ElfSectionHeaderConstants.java`.
//!
//! Provides constants for:
//! - Frequently used section name strings
//! - Section header type values (SHT_NULL through SHT_RELR)
//! - OS-specific and GNU-specific section types
//! - LLVM-specific section types
//! - Section header flag bits (SHF_WRITE through SHF_MASKPROC)
//! - Special section index values (SHN_UNDEF through SHN_HIRESERVE)

// ---------------------------------------------------------------------------
// Frequently Used Section Names
// ---------------------------------------------------------------------------

/// `.bss` section name.
pub const DOT_BSS: &str = ".bss";
/// `.comment` section name.
pub const DOT_COMMENT: &str = ".comment";
/// `.data` section name.
pub const DOT_DATA: &str = ".data";
/// `.data1` section name.
pub const DOT_DATA1: &str = ".data1";
/// `.debug` section name.
pub const DOT_DEBUG: &str = ".debug";
/// `.dynamic` section name.
pub const DOT_DYNAMIC: &str = ".dynamic";
/// `.dynstr` section name.
pub const DOT_DYNSTR: &str = ".dynstr";
/// `.dynsym` section name.
pub const DOT_DYNSYM: &str = ".dynsym";
/// `.fini` section name.
pub const DOT_FINI: &str = ".fini";
/// `.got` section name.
pub const DOT_GOT: &str = ".got";
/// `.hash` section name.
pub const DOT_HASH: &str = ".hash";
/// `.init` section name.
pub const DOT_INIT: &str = ".init";
/// `.interp` section name.
pub const DOT_INTERP: &str = ".interp";
/// `.line` section name.
pub const DOT_LINE: &str = ".line";
/// `.note` section name.
pub const DOT_NOTE: &str = ".note";
/// `.plt` section name.
pub const DOT_PLT: &str = ".plt";
/// `.rodata` section name.
pub const DOT_RODATA: &str = ".rodata";
/// `.rodata1` section name.
pub const DOT_RODATA1: &str = ".rodata1";
/// `.shstrtab` section name.
pub const DOT_SHSTRTAB: &str = ".shstrtab";
/// `.strtab` section name.
pub const DOT_STRTAB: &str = ".strtab";
/// `.symtab` section name.
pub const DOT_SYMTAB: &str = ".symtab";
/// `.text` section name.
pub const DOT_TEXT: &str = ".text";
/// `.tbss` section name.
pub const DOT_TBSS: &str = ".tbss";
/// `.tdata` section name.
pub const DOT_TDATA: &str = ".tdata";
/// `.tdata1` section name.
pub const DOT_TDATA1: &str = ".tdata1";

// ---------------------------------------------------------------------------
// Section Header Types (sh_type values)
// ---------------------------------------------------------------------------

/// Inactive section header.
pub const SHT_NULL: u32 = 0;
/// Program defined section.
pub const SHT_PROGBITS: u32 = 1;
/// Symbol table for link editing and dynamic linking.
pub const SHT_SYMTAB: u32 = 2;
/// String table.
pub const SHT_STRTAB: u32 = 3;
/// Relocation entries with explicit addends.
pub const SHT_RELA: u32 = 4;
/// Symbol hash table for dynamic linking.
pub const SHT_HASH: u32 = 5;
/// Dynamic linking information.
pub const SHT_DYNAMIC: u32 = 6;
/// Section holds information that marks the file.
pub const SHT_NOTE: u32 = 7;
/// Section contains no bytes.
pub const SHT_NOBITS: u32 = 8;
/// Relocation entries without explicit addends.
pub const SHT_REL: u32 = 9;
/// Undefined.
pub const SHT_SHLIB: u32 = 10;
/// Symbol table for dynamic linking.
pub const SHT_DYNSYM: u32 = 11;
/// Array of constructors.
pub const SHT_INIT_ARRAY: u32 = 14;
/// Array of destructors.
pub const SHT_FINI_ARRAY: u32 = 15;
/// Array of pre-constructors.
pub const SHT_PREINIT_ARRAY: u32 = 16;
/// Section group.
pub const SHT_GROUP: u32 = 17;
/// Extended section index table for linked symbol table.
pub const SHT_SYMTAB_SHNDX: u32 = 18;
/// Relative relocation table section.
pub const SHT_RELR: u32 = 19;

// ---------------------------------------------------------------------------
// OS-Specific Section Types
// ---------------------------------------------------------------------------

/// Android relocation entries without explicit addends.
pub const SHT_ANDROID_REL: u32 = 0x60000001;
/// Android relocation entries with explicit addends.
pub const SHT_ANDROID_RELA: u32 = 0x60000002;
/// Android's experimental support for SHT_RELR sections.
pub const SHT_ANDROID_RELR: u32 = 0x6fffff00;

// ---------------------------------------------------------------------------
// LLVM-Specific Section Types
// ---------------------------------------------------------------------------

/// LLVM ODR table.
pub const SHT_LLVM_ODRTAB: u32 = 0x6fff4c00;
/// LLVM Linker Options.
pub const SHT_LLVM_LINKER_OPTIONS: u32 = 0x6fff4c01;
/// List of address-significant symbols for safe ICF.
pub const SHT_LLVM_ADDRSIG: u32 = 0x6fff4c03;
/// LLVM Dependent Library Specifiers.
pub const SHT_LLVM_DEPENDENT_LIBRARIES: u32 = 0x6fff4c04;
/// Symbol partition specification.
pub const SHT_LLVM_SYMPART: u32 = 0x6fff4c05;
/// ELF header for loadable partition.
pub const SHT_LLVM_PART_EHDR: u32 = 0x6fff4c06;
/// Phdrs for loadable partition.
pub const SHT_LLVM_PART_PHDR: u32 = 0x6fff4c07;
/// LLVM Basic Block Address Map (old version, kept for backward compatibility).
pub const SHT_LLVM_BB_ADDR_MAP_V0: u32 = 0x6fff4c08;
/// LLVM Call Graph Profile.
pub const SHT_LLVM_CALL_GRAPH_PROFILE: u32 = 0x6fff4c09;
/// LLVM Basic Block Address Map.
pub const SHT_LLVM_BB_ADDR_MAP: u32 = 0x6fff4c0a;
/// LLVM device offloading data.
pub const SHT_LLVM_OFFLOADING: u32 = 0x6fff4c0b;
/// `.llvm.lto` for fat LTO.
pub const SHT_LLVM_LTO: u32 = 0x6fff4c0c;

// ---------------------------------------------------------------------------
// GNU-Specific Section Types
// ---------------------------------------------------------------------------

/// Object attributes.
pub const SHT_GNU_ATTRIBUTES: u32 = 0x6ffffff5;
/// GNU-style hash table.
pub const SHT_GNU_HASH: u32 = 0x6ffffff6;
/// Prelink library list.
pub const SHT_GNU_LIBLIST: u32 = 0x6ffffff7;
/// Checksum for DSO content.
pub const SHT_CHECKSUM: u32 = 0x6ffffff8;

// ---------------------------------------------------------------------------
// Sun-Specific Section Types
// ---------------------------------------------------------------------------

/// Sun move section.
pub const SHT_SUNW_MOVE: u32 = 0x6ffffffa;
/// Sun COMDAT section.
pub const SHT_SUNW_COMDAT: u32 = 0x6ffffffb;
/// Sun syminfo section.
pub const SHT_SUNW_SYMINFO: u32 = 0x6ffffffc;

// ---------------------------------------------------------------------------
// GNU Version Section Types
// ---------------------------------------------------------------------------

/// Version definition section.
pub const SHT_GNU_VERDEF: u32 = 0x6ffffffd;
/// Version needs section.
pub const SHT_GNU_VERNEED: u32 = 0x6ffffffe;
/// Version symbol table.
pub const SHT_GNU_VERSYM: u32 = 0x6fffffff;

// ---------------------------------------------------------------------------
// Section Header Flag Bits (sh_flags values)
// ---------------------------------------------------------------------------

/// The section contains data that should be writable during process execution.
pub const SHF_WRITE: u64 = 0x1;
/// The section occupies memory during execution.
pub const SHF_ALLOC: u64 = 0x2;
/// The section contains executable machine instructions.
pub const SHF_EXECINSTR: u64 = 0x4;
/// The section might be merged.
pub const SHF_MERGE: u64 = 0x10;
/// The section contains null-terminated strings.
pub const SHF_STRINGS: u64 = 0x20;
/// `sh_info` contains SHT index.
pub const SHF_INFO_LINK: u64 = 0x40;
/// Preserve order after combining.
pub const SHF_LINK_ORDER: u64 = 0x80;
/// Non-standard OS specific handling required.
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
/// The section is member of a group.
pub const SHF_GROUP: u64 = 0x200;
/// The section holds thread-local data.
pub const SHF_TLS: u64 = 0x400;
/// The bytes of the section are compressed.
pub const SHF_COMPRESSED: u64 = 0x800;
/// This section is excluded from the final executable or shared library.
pub const SHF_EXCLUDE: u64 = 0x80000000;
/// The section contains OS-specific data.
pub const SHF_MASKOS: u64 = 0x0ff00000;
/// Processor-specific.
pub const SHF_MASKPROC: u64 = 0xf0000000;

// ---------------------------------------------------------------------------
// Special Section Index Values (stored as 16-bit value)
// ---------------------------------------------------------------------------

/// Undefined, missing, or irrelevant section.
pub const SHN_UNDEF: u16 = 0x0000;
/// Lower bound on range of reserved indexes.
pub const SHN_LORESERVE: u16 = 0xff00;
/// Lower bound for processor-specific semantics.
pub const SHN_LOPROC: u16 = 0xff00;
/// Upper bound for processor-specific semantics.
pub const SHN_HIPROC: u16 = 0xff1f;
/// Lowest operating system-specific index.
pub const SHN_LOOS: u16 = 0xff20;
/// Highest operating system-specific index.
pub const SHN_HIOS: u16 = 0xff3f;
/// Symbol defined relative to this are absolute, not affected by relocation.
pub const SHN_ABS: u16 = 0xfff1;
/// Common symbols, such as Fortran COMMON or unallocated C external vars.
pub const SHN_COMMON: u16 = 0xfff2;
/// Mark that the index is >= SHN_LORESERVE.
pub const SHN_XINDEX: u16 = 0xffff;
/// Upper bound on range of reserved indexes.
pub const SHN_HIRESERVE: u16 = 0xffff;

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Returns a human-readable name for the given section header type.
///
/// # Arguments
///
/// * `sh_type` - The `sh_type` value from the section header.
///
/// # Returns
///
/// A static string slice with the type name (e.g., `"SHT_PROGBITS"`).
pub fn section_header_type_name(sh_type: u32) -> &'static str {
    match sh_type {
        SHT_NULL => "SHT_NULL",
        SHT_PROGBITS => "SHT_PROGBITS",
        SHT_SYMTAB => "SHT_SYMTAB",
        SHT_STRTAB => "SHT_STRTAB",
        SHT_RELA => "SHT_RELA",
        SHT_HASH => "SHT_HASH",
        SHT_DYNAMIC => "SHT_DYNAMIC",
        SHT_NOTE => "SHT_NOTE",
        SHT_NOBITS => "SHT_NOBITS",
        SHT_REL => "SHT_REL",
        SHT_SHLIB => "SHT_SHLIB",
        SHT_DYNSYM => "SHT_DYNSYM",
        SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
        SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
        SHT_PREINIT_ARRAY => "SHT_PREINIT_ARRAY",
        SHT_GROUP => "SHT_GROUP",
        SHT_SYMTAB_SHNDX => "SHT_SYMTAB_SHNDX",
        SHT_RELR => "SHT_RELR",
        SHT_ANDROID_REL => "SHT_ANDROID_REL",
        SHT_ANDROID_RELA => "SHT_ANDROID_RELA",
        SHT_ANDROID_RELR => "SHT_ANDROID_RELR",
        SHT_GNU_ATTRIBUTES => "SHT_GNU_ATTRIBUTES",
        SHT_GNU_HASH => "SHT_GNU_HASH",
        SHT_GNU_LIBLIST => "SHT_GNU_LIBLIST",
        SHT_CHECKSUM => "SHT_CHECKSUM",
        SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
        SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
        SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
        _ => "SHT_UNKNOWN",
    }
}

/// Returns a human-readable name for the given special section index.
///
/// # Arguments
///
/// * `shndx` - The section index value.
///
/// # Returns
///
/// A static string slice with the section index name (e.g., `"SHN_UNDEF"`),
/// or `None` if the index is a regular section number.
pub fn special_section_index_name(shndx: u16) -> Option<&'static str> {
    match shndx {
        SHN_UNDEF => Some("SHN_UNDEF"),
        SHN_LORESERVE => Some("SHN_LORESERVE"),
        SHN_ABS => Some("SHN_ABS"),
        SHN_COMMON => Some("SHN_COMMON"),
        SHN_XINDEX => Some("SHN_XINDEX"),
        SHN_HIRESERVE => Some("SHN_HIRESERVE"),
        _ => {
            if shndx >= SHN_LOPROC && shndx <= SHN_HIPROC {
                Some("SHN_LOPROC..SHN_HIPROC")
            } else if shndx >= SHN_LOOS && shndx <= SHN_HIOS {
                Some("SHN_LOOS..SHN_HIOS")
            } else {
                None // Regular section index
            }
        }
    }
}

/// Returns `true` if the given section index is a reserved/special value.
///
/// # Arguments
///
/// * `shndx` - The section index value.
pub fn is_special_section_index(shndx: u16) -> bool {
    shndx >= SHN_LORESERVE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_type_constants() {
        assert_eq!(SHT_NULL, 0);
        assert_eq!(SHT_PROGBITS, 1);
        assert_eq!(SHT_SYMTAB, 2);
        assert_eq!(SHT_STRTAB, 3);
        assert_eq!(SHT_RELA, 4);
        assert_eq!(SHT_HASH, 5);
        assert_eq!(SHT_DYNAMIC, 6);
        assert_eq!(SHT_NOTE, 7);
        assert_eq!(SHT_NOBITS, 8);
        assert_eq!(SHT_REL, 9);
        assert_eq!(SHT_SHLIB, 10);
        assert_eq!(SHT_DYNSYM, 11);
        assert_eq!(SHT_INIT_ARRAY, 14);
        assert_eq!(SHT_FINI_ARRAY, 15);
        assert_eq!(SHT_PREINIT_ARRAY, 16);
        assert_eq!(SHT_GROUP, 17);
        assert_eq!(SHT_SYMTAB_SHNDX, 18);
        assert_eq!(SHT_RELR, 19);
    }

    #[test]
    fn test_section_flag_constants() {
        assert_eq!(SHF_WRITE, 0x1);
        assert_eq!(SHF_ALLOC, 0x2);
        assert_eq!(SHF_EXECINSTR, 0x4);
        assert_eq!(SHF_MERGE, 0x10);
        assert_eq!(SHF_STRINGS, 0x20);
        assert_eq!(SHF_INFO_LINK, 0x40);
        assert_eq!(SHF_LINK_ORDER, 0x80);
        assert_eq!(SHF_OS_NONCONFORMING, 0x100);
        assert_eq!(SHF_GROUP, 0x200);
        assert_eq!(SHF_TLS, 0x400);
        assert_eq!(SHF_COMPRESSED, 0x800);
        assert_eq!(SHF_EXCLUDE, 0x80000000);
    }

    #[test]
    fn test_special_section_indices() {
        assert_eq!(SHN_UNDEF, 0x0000);
        assert_eq!(SHN_LORESERVE, 0xff00);
        assert_eq!(SHN_ABS, 0xfff1);
        assert_eq!(SHN_COMMON, 0xfff2);
        assert_eq!(SHN_XINDEX, 0xffff);
        assert_eq!(SHN_HIRESERVE, 0xffff);
    }

    #[test]
    fn test_section_name_constants() {
        assert_eq!(DOT_BSS, ".bss");
        assert_eq!(DOT_DATA, ".data");
        assert_eq!(DOT_TEXT, ".text");
        assert_eq!(DOT_RODATA, ".rodata");
        assert_eq!(DOT_SYMTAB, ".symtab");
        assert_eq!(DOT_STRTAB, ".strtab");
        assert_eq!(DOT_DYNSYM, ".dynsym");
        assert_eq!(DOT_DYNAMIC, ".dynamic");
        assert_eq!(DOT_GOT, ".got");
        assert_eq!(DOT_PLT, ".plt");
    }

    #[test]
    fn test_section_header_type_name() {
        assert_eq!(section_header_type_name(SHT_NULL), "SHT_NULL");
        assert_eq!(section_header_type_name(SHT_PROGBITS), "SHT_PROGBITS");
        assert_eq!(section_header_type_name(SHT_SYMTAB), "SHT_SYMTAB");
        assert_eq!(section_header_type_name(SHT_DYNSYM), "SHT_DYNSYM");
        assert_eq!(section_header_type_name(SHT_NOBITS), "SHT_NOBITS");
        assert_eq!(section_header_type_name(SHT_GNU_HASH), "SHT_GNU_HASH");
        assert_eq!(section_header_type_name(0xFFFFFFFF), "SHT_UNKNOWN");
    }

    #[test]
    fn test_special_section_index_name() {
        assert_eq!(special_section_index_name(SHN_UNDEF), Some("SHN_UNDEF"));
        assert_eq!(special_section_index_name(SHN_ABS), Some("SHN_ABS"));
        assert_eq!(special_section_index_name(SHN_COMMON), Some("SHN_COMMON"));
        assert_eq!(special_section_index_name(1), None);
        assert_eq!(special_section_index_name(42), None);
    }

    #[test]
    fn test_is_special_section_index() {
        assert!(is_special_section_index(SHN_LORESERVE));
        assert!(is_special_section_index(SHN_ABS));
        assert!(is_special_section_index(SHN_COMMON));
        assert!(!is_special_section_index(0));
        assert!(!is_special_section_index(1));
        assert!(!is_special_section_index(SHN_LORESERVE - 1));
    }

    #[test]
    fn test_gnu_specific_types() {
        assert_eq!(SHT_GNU_ATTRIBUTES, 0x6ffffff5);
        assert_eq!(SHT_GNU_HASH, 0x6ffffff6);
        assert_eq!(SHT_GNU_VERDEF, 0x6ffffffd);
        assert_eq!(SHT_GNU_VERNEED, 0x6ffffffe);
        assert_eq!(SHT_GNU_VERSYM, 0x6fffffff);
    }

    #[test]
    fn test_llvm_specific_types() {
        assert_eq!(SHT_LLVM_ODRTAB, 0x6fff4c00);
        assert_eq!(SHT_LLVM_LINKER_OPTIONS, 0x6fff4c01);
        assert_eq!(SHT_LLVM_ADDRSIG, 0x6fff4c03);
        assert_eq!(SHT_LLVM_LTO, 0x6fff4c0c);
    }

    #[test]
    fn test_android_specific_types() {
        assert_eq!(SHT_ANDROID_REL, 0x60000001);
        assert_eq!(SHT_ANDROID_RELA, 0x60000002);
        assert_eq!(SHT_ANDROID_RELR, 0x6fffff00);
    }
}
