//! COFF symbol storage class constants ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.CoffSymbolStorageClass`.

/// No entry.
pub const C_NULL: u8 = 0;
/// Automatic variable.
pub const C_AUTO: u8 = 1;
/// External (public) symbol - globals and externs.
pub const C_EXT: u8 = 2;
/// Static (private) symbol.
pub const C_STAT: u8 = 3;
/// Register variable.
pub const C_REG: u8 = 4;
/// External definition.
pub const C_EXTDEF: u8 = 5;
/// Label.
pub const C_LABEL: u8 = 6;
/// Undefined label.
pub const C_ULABEL: u8 = 7;
/// Member of structure.
pub const C_MOS: u8 = 8;
/// Function argument.
pub const C_ARG: u8 = 9;
/// Structure tag.
pub const C_STRTAG: u8 = 10;
/// Member of union.
pub const C_MOU: u8 = 11;
/// Union tag.
pub const C_UNTAG: u8 = 12;
/// Type definition.
pub const C_TPDEF: u8 = 13;
/// Undefined static.
pub const C_USTATIC: u8 = 14;
/// Enumeration tag.
pub const C_ENTAG: u8 = 15;
/// Member of enumeration.
pub const C_MOE: u8 = 16;
/// Register parameter.
pub const C_REGPARAM: u8 = 17;
/// Bit field.
pub const C_FIELD: u8 = 18;
/// Automatic argument.
pub const C_AUTOARG: u8 = 19;
/// Dummy entry (end of block).
pub const C_LASTENT: u8 = 20;
/// ".bb" or ".eb" - beginning or end of block.
pub const C_BLOCK: u8 = 100;
/// ".bf" or ".ef" - beginning or end of function.
pub const C_FCN: u8 = 101;
/// End of structure.
pub const C_EOS: u8 = 102;
/// File name.
pub const C_FILE: u8 = 103;
/// Line number, reformatted as symbol.
pub const C_LINE: u8 = 104;
/// Duplicate tag.
pub const C_ALIAS: u8 = 105;
/// External symbol in dmert public lib.
pub const C_HIDDEN: u8 = 106;
/// Physical end of function.
pub const C_EFCN: u8 = 107;

/// Returns a human-readable name for the given storage class, if known.
pub fn storage_class_name(class: u8) -> Option<&'static str> {
    match class {
        C_NULL => Some("C_NULL"),
        C_AUTO => Some("C_AUTO"),
        C_EXT => Some("C_EXT"),
        C_STAT => Some("C_STAT"),
        C_REG => Some("C_REG"),
        C_EXTDEF => Some("C_EXTDEF"),
        C_LABEL => Some("C_LABEL"),
        C_ULABEL => Some("C_ULABEL"),
        C_MOS => Some("C_MOS"),
        C_ARG => Some("C_ARG"),
        C_STRTAG => Some("C_STRTAG"),
        C_MOU => Some("C_MOU"),
        C_UNTAG => Some("C_UNTAG"),
        C_TPDEF => Some("C_TPDEF"),
        C_USTATIC => Some("C_USTATIC"),
        C_ENTAG => Some("C_ENTAG"),
        C_MOE => Some("C_MOE"),
        C_REGPARAM => Some("C_REGPARAM"),
        C_FIELD => Some("C_FIELD"),
        C_AUTOARG => Some("C_AUTOARG"),
        C_LASTENT => Some("C_LASTENT"),
        C_BLOCK => Some("C_BLOCK"),
        C_FCN => Some("C_FCN"),
        C_EOS => Some("C_EOS"),
        C_FILE => Some("C_FILE"),
        C_LINE => Some("C_LINE"),
        C_ALIAS => Some("C_ALIAS"),
        C_HIDDEN => Some("C_HIDDEN"),
        C_EFCN => Some("C_EFCN"),
        _ => None,
    }
}

/// Returns true if the storage class represents an external symbol.
pub fn is_external(class: u8) -> bool {
    class == C_EXT || class == C_EXTDEF
}

/// Returns true if the storage class represents a debug symbol.
pub fn is_debug(class: u8) -> bool {
    matches!(
        class,
        C_BLOCK | C_FCN | C_EOS | C_FILE | C_LINE | C_EFCN
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_class_name() {
        assert_eq!(storage_class_name(C_EXT), Some("C_EXT"));
        assert_eq!(storage_class_name(C_STAT), Some("C_STAT"));
        assert_eq!(storage_class_name(200), None);
    }

    #[test]
    fn test_is_external() {
        assert!(is_external(C_EXT));
        assert!(is_external(C_EXTDEF));
        assert!(!is_external(C_STAT));
        assert!(!is_external(C_AUTO));
    }

    #[test]
    fn test_is_debug() {
        assert!(is_debug(C_FILE));
        assert!(is_debug(C_LINE));
        assert!(is_debug(C_BLOCK));
        assert!(!is_debug(C_EXT));
        assert!(!is_debug(C_STAT));
    }
}
