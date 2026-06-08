//! COFF symbol type constants ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.CoffSymbolType`.

/// Null type.
pub const T_NULL: i16 = 0x0000;
/// Void function argument.
pub const T_VOID: i16 = 0x0001;
/// char.
pub const T_CHAR: i16 = 0x0002;
/// short.
pub const T_SHORT: i16 = 0x0003;
/// int.
pub const T_INT: i16 = 0x0004;
/// long.
pub const T_LONG: i16 = 0x0005;
/// float.
pub const T_FLOAT: i16 = 0x0006;
/// double.
pub const T_DOUBLE: i16 = 0x0007;
/// struct.
pub const T_STRUCT: i16 = 0x0008;
/// union.
pub const T_UNION: i16 = 0x0009;
/// enum.
pub const T_ENUM: i16 = 0x000a;
/// member of enumeration.
pub const T_MOE: i16 = 0x000b;
/// unsigned char.
pub const T_UCHAR: i16 = 0x000c;
/// unsigned short.
pub const T_USHORT: i16 = 0x000d;
/// unsigned int.
pub const T_UINT: i16 = 0x000e;
/// unsigned long.
pub const T_ULONG: i16 = 0x000f;
/// long double.
pub const T_LONG_DOUBLE: i16 = 0x0010;

// Derived types
/// No derived type.
pub const DT_NON: i16 = 0x0000;
/// Pointer to T.
pub const DT_PTR: i16 = 0x0001;
/// Function returning T.
pub const DT_FCN: i16 = 0x0002;
/// Array of T.
pub const DT_ARY: i16 = 0x0003;

/// Returns the base type from a symbol type value.
///
/// Ported from `CoffSymbolType.getBaseType()`.
pub fn get_base_type(symbol_type: i16) -> i16 {
    symbol_type & 0xf
}

/// Returns the derived type from a symbol type value.
///
/// Ported from `CoffSymbolType.getDerivedType()`.
pub fn get_derived_type(symbol_type: i16) -> i16 {
    symbol_type & 0xf0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_types() {
        assert_eq!(get_base_type(T_NULL), 0);
        assert_eq!(get_base_type(T_CHAR), 2);
        assert_eq!(get_base_type(T_INT), 4);
        assert_eq!(get_base_type(T_FLOAT), 6);
        assert_eq!(get_base_type(T_DOUBLE), 7);
    }

    #[test]
    fn test_derived_types() {
        // Derived type constants are unshifted (0-3), stored in bits [7:4]
        // get_derived_type extracts bits [7:4] so the raw values need to be shifted
        assert_eq!(get_derived_type(DT_NON << 4), DT_NON << 4);
        assert_eq!(get_derived_type(DT_PTR << 4), DT_PTR << 4);
        assert_eq!(get_derived_type(DT_FCN << 4), DT_FCN << 4);
        assert_eq!(get_derived_type(DT_ARY << 4), DT_ARY << 4);
    }

    #[test]
    fn test_combined_type() {
        // A pointer to int: DT_PTR << 4 | T_INT
        let ptr_to_int: i16 = (DT_PTR << 4) | T_INT;
        assert_eq!(get_base_type(ptr_to_int), T_INT);
        assert_eq!(get_derived_type(ptr_to_int), DT_PTR << 4);
    }
}
