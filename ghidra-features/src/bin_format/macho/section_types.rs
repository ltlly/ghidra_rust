//! Mach-O section types, attributes, and section name constants ported from
//! Ghidra's `ghidra.app.util.bin.format.macho.SectionTypes`,
//! `ghidra.app.util.bin.format.macho.SectionAttributes`, and
//! `ghidra.app.util.bin.format.macho.SectionNames`.

// ---------------------------------------------------------------------------
// Section type mask and values
// ---------------------------------------------------------------------------

/// Mask to extract the section type from the flags field.
pub const SECTION_TYPE_MASK: u32 = 0x0000_00FF;

/// Regular section.
pub const S_REGULAR: u32 = 0x0;
/// Zero fill on demand section.
pub const S_ZEROFILL: u32 = 0x1;
/// Section with only literal C strings.
pub const S_CSTRING_LITERALS: u32 = 0x2;
/// Section with only 4-byte literals.
pub const S_4BYTE_LITERALS: u32 = 0x3;
/// Section with only 8-byte literals.
pub const S_8BYTE_LITERALS: u32 = 0x4;
/// Section with only pointers to literals.
pub const S_LITERAL_POINTERS: u32 = 0x5;
/// Section with only non-lazy symbol pointers.
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
/// Section with only lazy symbol pointers.
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
/// Section with only symbol stubs; byte size of stub in the reserved2 field.
pub const S_SYMBOL_STUBS: u32 = 0x8;
/// Section with only function pointers for initialization.
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
/// Section with only function pointers for termination.
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xA;
/// Section contains symbols that are to be coalesced.
pub const S_COALESCED: u32 = 0xB;
/// Zero fill on demand section (can be larger than 4 gigabytes).
pub const S_GB_ZEROFILL: u32 = 0xC;
/// Section with only pairs of function pointers for interposing.
pub const S_INTERPOSING: u32 = 0xD;
/// Section with only 16-byte literals.
pub const S_16BYTE_LITERALS: u32 = 0xE;
/// Section contains DTrace Object Format.
pub const S_DTRACE_DOF: u32 = 0xF;
/// Section with only lazy symbol pointers to lazy loaded dylibs.
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
/// Thread local regular section.
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
/// Thread local zero-fill section.
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
/// Thread local variable descriptors.
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
/// Pointers to thread local variable descriptors.
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
/// Functions to call to initialize thread local variable values.
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;

/// Returns the name of the section type, or `None` if unrecognized.
pub fn section_type_name(section_type: u32) -> Option<&'static str> {
    match section_type {
        S_REGULAR => Some("REGULAR"),
        S_ZEROFILL => Some("ZEROFILL"),
        S_CSTRING_LITERALS => Some("CSTRING_LITERALS"),
        S_4BYTE_LITERALS => Some("4BYTE_LITERALS"),
        S_8BYTE_LITERALS => Some("8BYTE_LITERALS"),
        S_LITERAL_POINTERS => Some("LITERAL_POINTERS"),
        S_NON_LAZY_SYMBOL_POINTERS => Some("NON_LAZY_SYMBOL_POINTERS"),
        S_LAZY_SYMBOL_POINTERS => Some("LAZY_SYMBOL_POINTERS"),
        S_SYMBOL_STUBS => Some("SYMBOL_STUBS"),
        S_MOD_INIT_FUNC_POINTERS => Some("MOD_INIT_FUNC_POINTERS"),
        S_MOD_TERM_FUNC_POINTERS => Some("MOD_TERM_FUNC_POINTERS"),
        S_COALESCED => Some("COALESCED"),
        S_GB_ZEROFILL => Some("GB_ZEROFILL"),
        S_INTERPOSING => Some("INTERPOSING"),
        S_16BYTE_LITERALS => Some("16BYTE_LITERALS"),
        S_DTRACE_DOF => Some("DTRACE_DOF"),
        S_LAZY_DYLIB_SYMBOL_POINTERS => Some("LAZY_DYLIB_SYMBOL_POINTERS"),
        S_THREAD_LOCAL_REGULAR => Some("THREAD_LOCAL_REGULAR"),
        S_THREAD_LOCAL_ZEROFILL => Some("THREAD_LOCAL_ZEROFILL"),
        S_THREAD_LOCAL_VARIABLES => Some("THREAD_LOCAL_VARIABLES"),
        S_THREAD_LOCAL_VARIABLE_POINTERS => Some("THREAD_LOCAL_VARIABLE_POINTERS"),
        S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => Some("THREAD_LOCAL_INIT_FUNCTION_POINTERS"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Section attribute masks and flags
// ---------------------------------------------------------------------------

/// Mask for the 24 section attribute bits.
pub const SECTION_ATTRIBUTES_MASK: u32 = 0xFFFF_FF00;

/// User-settable attributes.
pub const SECTION_ATTRIBUTES_USR: u32 = 0xFF00_0000;

/// System-settable attributes.
pub const SECTION_ATTRIBUTES_SYS: u32 = 0x00FF_FF00;

/// Section contains only true machine instructions.
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
/// Section contains coalesced symbols not to be in a ranlib table of contents.
pub const S_ATTR_NO_TOC: u32 = 0x4000_0000;
/// OK to strip static symbols in this section in files with the MH_DYLDLINK flag.
pub const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x2000_0000;
/// Section must not be dead-stripped.
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;
/// Section must be live when the image is loaded.
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;
/// Used with i386 code stubs written on by dyld.
pub const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x0400_0000;
/// Section contains some machine instructions.
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
/// Section has external relocation entries.
pub const S_ATTR_EXT_RELOC: u32 = 0x0000_0200;
/// Section has local relocation entries.
pub const S_ATTR_LOC_RELOC: u32 = 0x0000_0100;

/// Returns attribute flag names that are set in the given attributes value.
///
/// Each name is returned without the `S_ATTR_` prefix.
pub fn get_attribute_names(attributes: u32) -> Vec<&'static str> {
    const ATTR_TABLE: &[(u32, &str)] = &[
        (S_ATTR_PURE_INSTRUCTIONS, "PURE_INSTRUCTIONS"),
        (S_ATTR_NO_TOC, "NO_TOC"),
        (S_ATTR_STRIP_STATIC_SYMS, "STRIP_STATIC_SYMS"),
        (S_ATTR_NO_DEAD_STRIP, "NO_DEAD_STRIP"),
        (S_ATTR_LIVE_SUPPORT, "LIVE_SUPPORT"),
        (S_ATTR_SELF_MODIFYING_CODE, "SELF_MODIFYING_CODE"),
        (S_ATTR_SOME_INSTRUCTIONS, "SOME_INSTRUCTIONS"),
        (S_ATTR_EXT_RELOC, "EXT_RELOC"),
        (S_ATTR_LOC_RELOC, "LOC_RELOC"),
    ];
    ATTR_TABLE
        .iter()
        .filter(|(bit, _)| (attributes & bit) != 0)
        .map(|(_, name)| *name)
        .collect()
}

// ---------------------------------------------------------------------------
// Section name constants
// ---------------------------------------------------------------------------

/// The real text part of the text section; no headers, no padding.
pub const SECT_TEXT: &str = "__text";
/// Constant null-terminated C strings.
pub const SECT_CSTRING: &str = "__cstring";
/// Position-independent indirect symbol stubs.
pub const SECT_PICSYMBOL_STUB: &str = "__picsymbol_stub";
/// Indirect symbol stubs.
pub const SECT_SYMBOL_STUB: &str = "__symbol_stub";
/// Initialized constant variables.
pub const SECT_CONST: &str = "__const";
/// 4-byte literal values; single-precision floating point constants.
pub const SECT_LITERAL4: &str = "__literal4";
/// 8-byte literal values; double-precision floating point constants.
pub const SECT_LITERAL8: &str = "__literal8";
/// The fvmlib initialization section.
pub const SECT_FVMLIB_INIT0: &str = "__fvmlib_init0";
/// The section following the fvmlib initialization section.
pub const SECT_FVMLIB_INIT1: &str = "__fvmlib_init1";

/// The real initialized data section; no padding, no bss overlap.
pub const SECT_DATA: &str = "__data";
/// Lazy symbol pointers (indirect references to imported functions).
pub const SECT_LA_SYMBOL_PTR: &str = "__la_symbol_ptr";
/// Non-lazy symbol pointers (indirect references to imported functions).
pub const SECT_NL_SYMBOL_PTR: &str = "__nl_symbol_ptr";
/// Place holder section used by dynamic linker.
pub const SECT_DYLD: &str = "__dyld";
/// Initialized relocatable constant variables (data segment).
pub const SECT_DATA_CONST: &str = "__const";
/// Module initialization functions (C++ static constructors).
pub const SECT_MOD_INIT_FUNC: &str = "__mod_init_func";
/// Module termination functions.
pub const SECT_MOD_TERM_FUNC: &str = "__mod_term_func";
/// The real uninitialized data section; no padding.
pub const SECT_BSS: &str = "__bss";
/// The section common symbols are allocated in by the link editor.
pub const SECT_COMMON: &str = "__common";
/// Global offset table section.
pub const SECT_GOT: &str = "__got";

/// Stubs for calls to functions in a dynamic library.
pub const SECT_JUMP_TABLE: &str = "__jump_table";
/// Non-lazy symbol pointers (import).
pub const SECT_POINTERS: &str = "__pointers";
/// Section dedicated to holding global program variables.
pub const SECT_PROGRAM_VARS: &str = "__program_vars";

// Segment name constants (used in Section permission logic)
/// The __TEXT segment.
pub const SEG_TEXT: &str = "__TEXT";
/// The __TEXT_EXEC segment.
pub const SEG_TEXT_EXEC: &str = "__TEXT_EXEC";
/// The __PRELINK_TEXT segment.
pub const SEG_PRELINK_TEXT: &str = "__PRELINK_TEXT";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_type_name() {
        assert_eq!(section_type_name(S_REGULAR), Some("REGULAR"));
        assert_eq!(section_type_name(S_ZEROFILL), Some("ZEROFILL"));
        assert_eq!(section_type_name(S_CSTRING_LITERALS), Some("CSTRING_LITERALS"));
        assert_eq!(section_type_name(S_THREAD_LOCAL_VARIABLES), Some("THREAD_LOCAL_VARIABLES"));
        assert_eq!(section_type_name(0xFF), None);
    }

    #[test]
    fn test_section_type_mask() {
        assert_eq!(SECTION_TYPE_MASK, 0x0000_00FF);
        assert_eq!(0xABCD_0005 & SECTION_TYPE_MASK, S_4BYTE_LITERALS);
    }

    #[test]
    fn test_attribute_names_empty() {
        assert!(get_attribute_names(0).is_empty());
    }

    #[test]
    fn test_attribute_names() {
        let attrs = get_attribute_names(S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS);
        assert!(attrs.contains(&"PURE_INSTRUCTIONS"));
        assert!(attrs.contains(&"SOME_INSTRUCTIONS"));
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn test_section_name_constants() {
        assert_eq!(SECT_TEXT, "__text");
        assert_eq!(SECT_DATA, "__data");
        assert_eq!(SECT_GOT, "__got");
        assert_eq!(SECT_BSS, "__bss");
    }
}
