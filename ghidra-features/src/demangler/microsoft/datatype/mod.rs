//! Microsoft mangled data types.
//!
//! Ported from `mdemangler.datatype.*` Java classes.
//!
//! The type system uses an enum hierarchy:
//! - `DataType` covers basic C/C++ types (int, char, float, void, etc.)
//! - `ModifierType` covers pointers, references, const/volatile qualifiers
//! - `ComplexType` covers struct, union, enum, class
//! - `ExtendedType` covers extended types (bool, wchar_t, __int128, etc.)
//! - `FunctionType` is handled separately in the `function` submodule

pub mod parser;

use crate::demangler::microsoft::modifier::CVMod;
use std::fmt;

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/// Sign qualification for integer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sign {
    /// Signed (default).
    Signed,
    /// Explicitly `signed`.
    SpecifiedSigned,
    /// `unsigned`.
    Unsigned,
}

impl Default for Sign {
    fn default() -> Self {
        Sign::Signed
    }
}

// ---------------------------------------------------------------------------
// DataType
// ---------------------------------------------------------------------------

/// A data type in a Microsoft mangled symbol.
///
/// This corresponds to the Java `MDDataType` and its subtypes.
#[derive(Debug, Clone)]
pub enum DataType {
    // === Basic types (from MDDataType subtypes) ===
    Void,
    Bool,
    Char { sign: Sign },
    WChar,
    Char8,
    Char16,
    Char32,
    Short { sign: Sign },
    Int { sign: Sign },
    Long { sign: Sign },
    Int64 { sign: Sign },
    Int128 { sign: Sign },
    Float,
    Double,
    LongDouble,
    VarArgs,

    // === Pointer/Reference types ===
    Pointer {
        pointed_to: Box<DataType>,
        cv_mod: Option<CVMod>,
    },
    Reference {
        pointed_to: Box<DataType>,
        cv_mod: Option<CVMod>,
    },
    RightReference {
        pointed_to: Box<DataType>,
        cv_mod: Option<CVMod>,
    },
    PointerToDataMember {
        pointed_to: Box<DataType>,
        cv_mod: Option<CVMod>,
    },
    PointerToMemberFunction {
        pointed_to: Box<DataType>,
        cv_mod: Option<CVMod>,
    },

    // === Complex types ===
    Class { name: String },
    Struct { name: String },
    Union { name: String },
    Enum { name: String, underlying: Option<Box<DataType>> },

    // === Array ===
    Array {
        element_type: Box<DataType>,
        dimensions: Vec<u64>,
    },

    // === Modifier ===
    Const(Box<DataType>),
    Volatile(Box<DataType>),
    ConstVolatile(Box<DataType>),

    // === Null pointer ===
    NullPtr,

    // === Placeholder for incomplete parsing ===
    Unknown { code: String },
}

impl DataType {
    /// Returns true if this type is void.
    pub fn is_void(&self) -> bool {
        matches!(self, DataType::Void)
    }

    /// Returns true if this is a pointer or reference type.
    pub fn is_pointer_or_ref(&self) -> bool {
        matches!(
            self,
            DataType::Pointer { .. }
                | DataType::Reference { .. }
                | DataType::RightReference { .. }
                | DataType::PointerToDataMember { .. }
                | DataType::PointerToMemberFunction { .. }
        )
    }

    /// Emit the type name as a string.
    pub fn emit(&self) -> String {
        match self {
            DataType::Void => "void".to_string(),
            DataType::Bool => "bool".to_string(),
            DataType::Char { sign } => match sign {
                Sign::Unsigned => "unsigned char".to_string(),
                Sign::SpecifiedSigned => "signed char".to_string(),
                Sign::Signed => "char".to_string(),
            },
            DataType::WChar => "wchar_t".to_string(),
            DataType::Char8 => "char8_t".to_string(),
            DataType::Char16 => "char16_t".to_string(),
            DataType::Char32 => "char32_t".to_string(),
            DataType::Short { sign } => match sign {
                Sign::Unsigned => "unsigned short".to_string(),
                Sign::SpecifiedSigned => "signed short".to_string(),
                Sign::Signed => "short".to_string(),
            },
            DataType::Int { sign } => match sign {
                Sign::Unsigned => "unsigned int".to_string(),
                Sign::SpecifiedSigned => "signed int".to_string(),
                Sign::Signed => "int".to_string(),
            },
            DataType::Long { sign } => match sign {
                Sign::Unsigned => "unsigned long".to_string(),
                Sign::SpecifiedSigned => "signed long".to_string(),
                Sign::Signed => "long".to_string(),
            },
            DataType::Int64 { sign } => match sign {
                Sign::Unsigned => "unsigned __int64".to_string(),
                Sign::SpecifiedSigned => "signed __int64".to_string(),
                Sign::Signed => "__int64".to_string(),
            },
            DataType::Int128 { sign } => match sign {
                Sign::Unsigned => "unsigned __int128".to_string(),
                Sign::SpecifiedSigned => "signed __int128".to_string(),
                Sign::Signed => "__int128".to_string(),
            },
            DataType::Float => "float".to_string(),
            DataType::Double => "double".to_string(),
            DataType::LongDouble => "long double".to_string(),
            DataType::VarArgs => "...".to_string(),
            DataType::Pointer { pointed_to, cv_mod } => {
                let mut s = pointed_to.emit();
                s.push_str(" *");
                if let Some(cv) = cv_mod {
                    cv.emit_qualified(&mut s);
                }
                s
            }
            DataType::Reference { pointed_to, cv_mod } => {
                let mut s = pointed_to.emit();
                s.push_str(" &");
                if let Some(cv) = cv_mod {
                    cv.emit_qualified(&mut s);
                }
                s
            }
            DataType::RightReference {
                pointed_to,
                cv_mod,
            } => {
                let mut s = pointed_to.emit();
                s.push_str(" &&");
                if let Some(cv) = cv_mod {
                    cv.emit_qualified(&mut s);
                }
                s
            }
            DataType::PointerToDataMember {
                pointed_to,
                cv_mod,
            } => {
                let mut s = pointed_to.emit();
                s.push_str(" *");
                if let Some(cv) = cv_mod {
                    cv.emit_qualified(&mut s);
                }
                s
            }
            DataType::PointerToMemberFunction {
                pointed_to,
                cv_mod,
            } => {
                let mut s = pointed_to.emit();
                s.push_str(" *");
                if let Some(cv) = cv_mod {
                    cv.emit_qualified(&mut s);
                }
                s
            }
            DataType::Class { name }
            | DataType::Struct { name }
            | DataType::Union { name } => name.clone(),
            DataType::Enum { name, .. } => name.clone(),
            DataType::Array {
                element_type,
                dimensions,
            } => {
                let mut s = element_type.emit();
                for &dim in dimensions {
                    s.push_str(&format!("[{}]", dim));
                }
                s
            }
            DataType::Const(inner) => format!("{} const", inner.emit()),
            DataType::Volatile(inner) => format!("{} volatile", inner.emit()),
            DataType::ConstVolatile(inner) => format!("{} const volatile", inner.emit()),
            DataType::NullPtr => "std::nullptr_t".to_string(),
            DataType::Unknown { code } => format!("_UNKNOWN({})", code),
        }
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_types() {
        assert_eq!(DataType::Void.emit(), "void");
        assert_eq!(DataType::Bool.emit(), "bool");
        assert_eq!(
            DataType::Int {
                sign: Sign::Signed
            }
            .emit(),
            "int"
        );
        assert_eq!(
            DataType::Int {
                sign: Sign::Unsigned
            }
            .emit(),
            "unsigned int"
        );
        assert_eq!(
            DataType::Char {
                sign: Sign::SpecifiedSigned
            }
            .emit(),
            "signed char"
        );
    }

    #[test]
    fn test_pointer_type() {
        let dt = DataType::Pointer {
            pointed_to: Box::new(DataType::Int {
                sign: Sign::Signed,
            }),
            cv_mod: None,
        };
        assert_eq!(dt.emit(), "int *");
    }

    #[test]
    fn test_const_pointer() {
        let dt = DataType::Pointer {
            pointed_to: Box::new(DataType::Int {
                sign: Sign::Signed,
            }),
            cv_mod: Some(CVMod::new_const()),
        };
        assert!(dt.emit().contains("const"));
    }

    #[test]
    fn test_reference_type() {
        let dt = DataType::Reference {
            pointed_to: Box::new(DataType::Float),
            cv_mod: None,
        };
        assert_eq!(dt.emit(), "float &");
    }

    #[test]
    fn test_array_type() {
        let dt = DataType::Array {
            element_type: Box::new(DataType::Int {
                sign: Sign::Signed,
            }),
            dimensions: vec![10, 20],
        };
        assert_eq!(dt.emit(), "int[10][20]");
    }

    #[test]
    fn test_is_void() {
        assert!(DataType::Void.is_void());
        assert!(!DataType::Int {
            sign: Sign::Signed
        }
        .is_void());
    }
}
