//! COFF symbol section number constants ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.CoffSymbolSectionNumber`.

/// Special symbolic debugging symbol.
pub const N_DEBUG: i16 = -2;
/// Absolute symbols.
pub const N_ABS: i16 = -1;
/// Undefined external symbol.
pub const N_UNDEF: i16 = 0;
/// .text section symbol.
pub const N_TEXT: i16 = 1;
/// .data section symbol.
pub const N_DATA: i16 = 2;
/// .bss section symbol.
pub const N_BSS: i16 = 3;

// NOTE: Section number values 4 -> 32767 are reserved for user defined named
// sections in the order in which each section is defined.

/// Returns true if the section number represents a special/debug section.
pub fn is_special_section(section_number: i16) -> bool {
    section_number <= 0
}

/// Returns true if the section number references a real section (1-based index).
pub fn is_real_section(section_number: i16) -> bool {
    section_number > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_special_sections() {
        assert!(is_special_section(N_DEBUG));
        assert!(is_special_section(N_ABS));
        assert!(is_special_section(N_UNDEF));
        assert!(!is_special_section(N_TEXT));
        assert!(!is_special_section(N_DATA));
    }

    #[test]
    fn test_real_sections() {
        assert!(is_real_section(N_TEXT));
        assert!(is_real_section(N_DATA));
        assert!(is_real_section(N_BSS));
        assert!(is_real_section(10));
        assert!(!is_real_section(N_UNDEF));
        assert!(!is_real_section(N_ABS));
    }
}
