//! ELF (Executable and Linkable Format) binary format types.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.elf` Java package.
//!
//! This module provides Rust equivalents of the core ELF data structures,
//! constants, and type registries used throughout Ghidra's ELF loader and
//! analyzers.  The types are split across focused submodules:
//!
//! - [`elf_constants`] -- identification indices, magic bytes, file classes,
//!   data encodings, OS/ABI values, file types, and machine types
//! - [`elf_section_header_constants`] -- section header types (SHT_*),
//!   flag bits (SHF_*), special section indices (SHN_*), and standard
//!   section name strings
//! - [`elf_program_header_constants`] -- segment types (PT_*), segment
//!   flag bits (PF_*), and helper predicates
//! - [`elf_dynamic_type`] -- dynamic entry types (DT_*), flag values
//!   (DF_*, DF_1_*), and a lookup registry
//! - [`elf_exception`] -- the [`ElfException`] error type for ELF parsing
//!
//! # Usage
//!
//! ```
//! use ghidra_features::bin_format::elf::*;
//!
//! // Check ELF magic
//! assert_eq!(MAGIC_BYTES, [0x7f, b'E', b'L', b'F']);
//!
//! // Look up a machine name
//! assert_eq!(elf_machine_name(EM_X86_64), "EM_X86_64");
//!
//! // Look up a dynamic tag
//! assert_eq!(dynamic_tag_name(1), "DT_NEEDED");
//! ```

pub mod elf_constants;
pub mod elf_dynamic_type;
pub mod elf_exception;
pub mod elf_program_header_constants;
pub mod elf_program_header_type;
pub mod elf_section_header_constants;
pub mod elf_section_header_type;
pub mod elf_string_table;

// Re-export all constants from elf_constants at the module level
pub use elf_constants::*;

// Re-export section header constants
pub use elf_section_header_constants::{
    DOT_BSS, DOT_COMMENT, DOT_DATA, DOT_DATA1, DOT_DEBUG, DOT_DYNAMIC, DOT_DYNSTR, DOT_DYNSYM,
    DOT_FINI, DOT_GOT, DOT_HASH, DOT_INIT, DOT_INTERP, DOT_LINE, DOT_NOTE, DOT_PLT, DOT_RODATA,
    DOT_RODATA1, DOT_SHSTRTAB, DOT_STRTAB, DOT_SYMTAB, DOT_TBSS, DOT_TDATA, DOT_TDATA1,
    DOT_TEXT, SHF_ALLOC, SHF_COMPRESSED, SHF_EXCLUDE, SHF_EXECINSTR, SHF_GROUP, SHF_INFO_LINK,
    SHF_LINK_ORDER, SHF_MASKOS, SHF_MASKPROC, SHF_MERGE, SHF_OS_NONCONFORMING, SHF_STRINGS,
    SHF_TLS, SHF_WRITE, SHN_ABS, SHN_COMMON, SHN_HIRESERVE, SHN_HIOS, SHN_LOOS, SHN_LOPROC,
    SHN_LORESERVE, SHN_UNDEF, SHN_XINDEX, SHT_ANDROID_RELA, SHT_ANDROID_REL, SHT_ANDROID_RELR,
    SHT_CHECKSUM, SHT_DYNAMIC, SHT_DYNSYM, SHT_FINI_ARRAY, SHT_GNU_ATTRIBUTES, SHT_GNU_HASH,
    SHT_GNU_LIBLIST, SHT_GNU_VERDEF, SHT_GNU_VERNEED, SHT_GNU_VERSYM, SHT_GROUP, SHT_HASH,
    SHT_INIT_ARRAY, SHT_LLVM_ADDRSIG, SHT_LLVM_BB_ADDR_MAP, SHT_LLVM_BB_ADDR_MAP_V0,
    SHT_LLVM_CALL_GRAPH_PROFILE, SHT_LLVM_DEPENDENT_LIBRARIES, SHT_LLVM_LINKER_OPTIONS,
    SHT_LLVM_LTO, SHT_LLVM_ODRTAB, SHT_LLVM_OFFLOADING, SHT_LLVM_PART_EHDR,
    SHT_LLVM_PART_PHDR, SHT_LLVM_SYMPART, SHT_NOBITS, SHT_NOTE, SHT_NULL, SHT_PREINIT_ARRAY,
    SHT_PROGBITS, SHT_REL, SHT_RELA, SHT_RELR, SHT_SHLIB, SHT_STRTAB, SHT_SUNW_COMDAT,
    SHT_SUNW_MOVE, SHT_SUNW_SYMINFO, SHT_SYMTAB, SHT_SYMTAB_SHNDX,
    is_special_section_index, section_header_type_name, special_section_index_name,
};

// Re-export program header constants
pub use elf_program_header_constants::{
    PF_MASKOS, PF_MASKPROC, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_EH_FRAME, PT_GNU_RELRO,
    PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_NOTE, PT_NULL, PT_PHDR, PT_SHLIB, PT_SUNWSTACK,
    PT_SUNWBSS, PT_TLS, is_loadable_segment, is_os_specific_segment,
    is_processor_specific_segment, program_header_flags_string, program_header_type_name,
};

// Re-export dynamic type types and lookup functions
pub use elf_dynamic_type::{
    DF_1_DIRECT, DF_1_GLOBAL, DF_1_GROUP, DF_1_INITFIRST, DF_1_NODEFLIB, DF_1_NODELETE,
    DF_1_NOOPEN, DF_1_NOW, DF_1_ORIGIN, DF_BIND_NOW, DF_ORIGIN, DF_STATIC_TLS, DF_SYMBOLIC,
    DF_TEXTREL, DT_ANDROID_RELA, DT_ANDROID_RELASZ, DT_ANDROID_RELR, DT_ANDROID_RELRENT,
    DT_ANDROID_RELRSZ, DT_ANDROID_REL, DT_ANDROID_RELSZ, DT_AUDIT, DT_AUXILIARY, DT_BIND_NOW,
    DT_CHECKSUM, DT_CONFIG, DT_DEBUG, DT_DEPAUDIT, DT_FEATURE_1, DT_FILTER, DT_FINI,
    DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS, DT_FLAGS_1, DT_GNU_CONFLICT, DT_GNU_CONFLICTSZ,
    DT_GNU_HASH, DT_GNU_LIBLIST, DT_GNU_LIBLISTSZ, DT_GNU_PRELINKED, DT_VERDEF,
    DT_VERDEFNUM, DT_VERNEED, DT_VERNEEDNUM, DT_GNU_XHASH, DT_HASH, DT_INIT,
    DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL, DT_MOVEENT, DT_MOVESZ, DT_MOVETAB, DT_NEEDED,
    DT_NULL, DT_PLTPAD, DT_PLTPADSZ, DT_PLTGOT, DT_PLTREL, DT_PLTRELSZ, DT_POSFLAG_1,
    DT_RELA, DT_RELAENT, DT_RELACOUNT, DT_RELASZ, DT_REL, DT_RELCOUNT, DT_RELENT, DT_RELSZ,
    DT_RELR, DT_RELRENT, DT_RELRSZ, DT_RPATH, DT_RUNPATH, DT_SONAME, DT_STRSZ, DT_STRTAB,
    DT_SYMBOLIC, DT_SYMENT, DT_SYMINENT, DT_SYMINSZ, DT_SYMINFO, DT_SYMTAB, DT_TEXTREL,
    DT_TLSDESC_GOT, DT_TLSDESC_PLT, DT_VERSYM, ElfDynamicType, ElfDynamicValueType,
    dynamic_tag_name, is_address_dynamic_tag, is_string_dynamic_tag, lookup_dynamic_type,
};

// Re-export exception type
pub use elf_exception::ElfException;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_bytes() {
        assert_eq!(MAGIC_BYTES, [0x7f, b'E', b'L', b'F']);
    }

    #[test]
    fn test_elf_class_64() {
        assert_eq!(ELF_CLASS_64, 2);
    }

    #[test]
    fn test_machine_name_x86_64() {
        assert_eq!(elf_machine_name(EM_X86_64), "EM_X86_64");
    }

    #[test]
    fn test_section_type_lookup() {
        assert_eq!(section_header_type_name(SHT_PROGBITS), "SHT_PROGBITS");
    }

    #[test]
    fn test_program_header_type_lookup() {
        assert_eq!(program_header_type_name(PT_LOAD), "PT_LOAD");
    }

    #[test]
    fn test_dynamic_tag_lookup() {
        assert_eq!(dynamic_tag_name(1), "DT_NEEDED");
    }

    #[test]
    fn test_exception_creation() {
        let exc = ElfException::new("test error");
        assert!(format!("{}", exc).contains("test error"));
    }

    #[test]
    fn test_section_names() {
        assert_eq!(DOT_TEXT, ".text");
        assert_eq!(DOT_DATA, ".data");
        assert_eq!(DOT_BSS, ".bss");
    }

    #[test]
    fn test_re_export_completeness() {
        // Verify key constants from each submodule are accessible
        // elf_constants
        let _ = ET_EXEC;
        let _ = EM_ARM;
        // section header constants
        let _ = SHF_WRITE;
        let _ = SHN_UNDEF;
        // program header constants
        let _ = PF_X;
        let _ = PT_GNU_STACK;
        // dynamic type
        let _ = DT_GNU_HASH;
        let _ = DF_1_NOW;
        // exception
        let _ = ElfException::new("ok");
    }
}
