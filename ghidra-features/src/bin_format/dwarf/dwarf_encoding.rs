//! DWARF attribute encoding constants ported from Ghidra's
//! `ghidra.app.util.bin.format.dwarf.DWARFEncoding`.
//!
//! Constants from the DWARF4 specification (www.dwarfstd.org/doc/DWARF4.pdf).

/// DWARF attribute encoding constants (DW_ATE_*).
///
/// These define the encoding of base types in DWARF debugging information.
pub struct DwarfEncoding;

impl DwarfEncoding {
    pub const DW_ATE_VOID: u32 = 0x0;
    pub const DW_ATE_ADDRESS: u32 = 0x1;
    pub const DW_ATE_BOOLEAN: u32 = 0x2;
    pub const DW_ATE_COMPLEX_FLOAT: u32 = 0x3;
    pub const DW_ATE_FLOAT: u32 = 0x4;
    pub const DW_ATE_SIGNED: u32 = 0x5;
    pub const DW_ATE_SIGNED_CHAR: u32 = 0x6;
    pub const DW_ATE_UNSIGNED: u32 = 0x7;
    pub const DW_ATE_UNSIGNED_CHAR: u32 = 0x8;
    pub const DW_ATE_IMAGINARY_FLOAT: u32 = 0x9;
    pub const DW_ATE_PACKED_DECIMAL: u32 = 0xa;
    pub const DW_ATE_NUMERIC_STRING: u32 = 0xb;
    pub const DW_ATE_EDITED: u32 = 0xc;
    pub const DW_ATE_SIGNED_FIXED: u32 = 0xd;
    pub const DW_ATE_UNSIGNED_FIXED: u32 = 0xe;
    pub const DW_ATE_DECIMAL_FLOAT: u32 = 0xf;
    pub const DW_ATE_UTF: u32 = 0x10;
    pub const DW_ATE_LO_USER: u32 = 0x80;
    pub const DW_ATE_HI_USER: u32 = 0xff;

    /// Returns a human-readable type name for the given encoding value.
    ///
    /// Strips the "DW_ATE_" prefix if present, otherwise returns "unknown_type_encoding".
    pub fn get_type_name(encoding: u32) -> &'static str {
        match encoding {
            Self::DW_ATE_VOID => "void",
            Self::DW_ATE_ADDRESS => "address",
            Self::DW_ATE_BOOLEAN => "boolean",
            Self::DW_ATE_COMPLEX_FLOAT => "complex_float",
            Self::DW_ATE_FLOAT => "float",
            Self::DW_ATE_SIGNED => "signed",
            Self::DW_ATE_SIGNED_CHAR => "signed_char",
            Self::DW_ATE_UNSIGNED => "unsigned",
            Self::DW_ATE_UNSIGNED_CHAR => "unsigned_char",
            Self::DW_ATE_IMAGINARY_FLOAT => "imaginary_float",
            Self::DW_ATE_PACKED_DECIMAL => "packed_decimal",
            Self::DW_ATE_NUMERIC_STRING => "numeric_string",
            Self::DW_ATE_EDITED => "edited",
            Self::DW_ATE_SIGNED_FIXED => "signed_fixed",
            Self::DW_ATE_UNSIGNED_FIXED => "unsigned_fixed",
            Self::DW_ATE_DECIMAL_FLOAT => "decimal_float",
            Self::DW_ATE_UTF => "UTF",
            _ => "unknown_type_encoding",
        }
    }

    /// Returns true if the encoding represents a signed integer type.
    pub fn is_signed(encoding: u32) -> bool {
        matches!(
            encoding,
            Self::DW_ATE_SIGNED | Self::DW_ATE_SIGNED_CHAR | Self::DW_ATE_SIGNED_FIXED
        )
    }

    /// Returns true if the encoding represents an unsigned integer type.
    pub fn is_unsigned(encoding: u32) -> bool {
        matches!(
            encoding,
            Self::DW_ATE_UNSIGNED
                | Self::DW_ATE_UNSIGNED_CHAR
                | Self::DW_ATE_UNSIGNED_FIXED
                | Self::DW_ATE_BOOLEAN
        )
    }

    /// Returns true if the encoding represents a floating point type.
    pub fn is_float(encoding: u32) -> bool {
        matches!(
            encoding,
            Self::DW_ATE_FLOAT
                | Self::DW_ATE_COMPLEX_FLOAT
                | Self::DW_ATE_IMAGINARY_FLOAT
                | Self::DW_ATE_DECIMAL_FLOAT
        )
    }

    /// Returns true if the encoding represents a character type.
    pub fn is_character(encoding: u32) -> bool {
        matches!(encoding, Self::DW_ATE_SIGNED_CHAR | Self::DW_ATE_UNSIGNED_CHAR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_type_name() {
        assert_eq!(DwarfEncoding::get_type_name(0x0), "void");
        assert_eq!(DwarfEncoding::get_type_name(0x4), "float");
        assert_eq!(DwarfEncoding::get_type_name(0x5), "signed");
        assert_eq!(DwarfEncoding::get_type_name(0x7), "unsigned");
        assert_eq!(DwarfEncoding::get_type_name(0x10), "UTF");
        assert_eq!(DwarfEncoding::get_type_name(0xff), "unknown_type_encoding");
    }

    #[test]
    fn test_is_signed() {
        assert!(DwarfEncoding::is_signed(DwarfEncoding::DW_ATE_SIGNED));
        assert!(DwarfEncoding::is_signed(DwarfEncoding::DW_ATE_SIGNED_CHAR));
        assert!(DwarfEncoding::is_signed(DwarfEncoding::DW_ATE_SIGNED_FIXED));
        assert!(!DwarfEncoding::is_signed(DwarfEncoding::DW_ATE_UNSIGNED));
    }

    #[test]
    fn test_is_unsigned() {
        assert!(DwarfEncoding::is_unsigned(DwarfEncoding::DW_ATE_UNSIGNED));
        assert!(DwarfEncoding::is_unsigned(DwarfEncoding::DW_ATE_BOOLEAN));
        assert!(!DwarfEncoding::is_unsigned(DwarfEncoding::DW_ATE_SIGNED));
    }

    #[test]
    fn test_is_float() {
        assert!(DwarfEncoding::is_float(DwarfEncoding::DW_ATE_FLOAT));
        assert!(DwarfEncoding::is_float(DwarfEncoding::DW_ATE_DECIMAL_FLOAT));
        assert!(!DwarfEncoding::is_float(DwarfEncoding::DW_ATE_SIGNED));
    }

    #[test]
    fn test_is_character() {
        assert!(DwarfEncoding::is_character(DwarfEncoding::DW_ATE_SIGNED_CHAR));
        assert!(DwarfEncoding::is_character(DwarfEncoding::DW_ATE_UNSIGNED_CHAR));
        assert!(!DwarfEncoding::is_character(DwarfEncoding::DW_ATE_UTF));
    }
}
