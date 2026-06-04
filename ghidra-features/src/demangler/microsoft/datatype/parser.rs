//! Data type parser for Microsoft mangled symbols.
//!
//! Ported from `MDDataTypeParser.java`.
//!
//! The parser has multiple levels:
//! - `parse_data_type()` -- top-level: handles modifiers (pointers, references)
//! - `parse_primary_data_type()` -- handles basic types, complex types, extended types
//! - `parse_basic_data_type()` -- handles single-character type codes

use super::{DataType, Sign};
use crate::demangler::microsoft::modifier::CVMod;

/// Parse a data type from the character stream.
///
/// This is the top-level entry point for type parsing. It handles
/// pointer/reference types which wrap an inner type.
///
/// # Arguments
/// * `chars` - The mangled symbol characters
/// * `index` - Current parse position (updated on return)
///
/// # Returns
/// The parsed `DataType`.
pub fn parse_data_type(chars: &[char], index: &mut usize) -> Result<DataType, String> {
    if *index >= chars.len() {
        return Err("Unexpected end of mangled symbol in type parsing".to_string());
    }

    let code = chars[*index];

    match code {
        // Pointer types: P, Q, R, S
        'P' => {
            *index += 1;
            let inner = parse_data_type(chars, index)?;
            Ok(DataType::Pointer {
                pointed_to: Box::new(inner),
                cv_mod: None,
            })
        }
        'Q' => {
            *index += 1;
            let inner = parse_data_type(chars, index)?;
            Ok(DataType::Reference {
                pointed_to: Box::new(inner),
                cv_mod: None,
            })
        }
        'R' => {
            *index += 1;
            let inner = parse_data_type(chars, index)?;
            Ok(DataType::RightReference {
                pointed_to: Box::new(inner),
                cv_mod: None,
            })
        }
        'S' => {
            *index += 1;
            let inner = parse_data_type(chars, index)?;
            // S is typically a pointer-to-member or similar
            Ok(DataType::Pointer {
                pointed_to: Box::new(inner),
                cv_mod: None,
            })
        }
        _ => parse_primary_data_type(chars, index),
    }
}

/// Parse a primary (non-pointer/non-reference) data type.
pub fn parse_primary_data_type(chars: &[char], index: &mut usize) -> Result<DataType, String> {
    if *index >= chars.len() {
        return Err("Unexpected end of mangled symbol in primary type parsing".to_string());
    }

    let code = chars[*index];

    match code {
        // Basic types
        'X' => { *index += 1; Ok(DataType::Void) }
        'C' => { *index += 1; Ok(DataType::Char { sign: Sign::SpecifiedSigned }) }
        'D' => { *index += 1; Ok(DataType::Int { sign: Sign::SpecifiedSigned }) }
        'E' => { *index += 1; Ok(DataType::Char { sign: Sign::Unsigned }) }
        'F' => { *index += 1; Ok(DataType::Short { sign: Sign::Signed }) }
        'G' => { *index += 1; Ok(DataType::Short { sign: Sign::Unsigned }) }
        'H' => { *index += 1; Ok(DataType::Int { sign: Sign::Signed }) }
        'I' => { *index += 1; Ok(DataType::Int { sign: Sign::Unsigned }) }
        'J' => { *index += 1; Ok(DataType::Long { sign: Sign::Signed }) }
        'K' => { *index += 1; Ok(DataType::Long { sign: Sign::Unsigned }) }
        'M' => { *index += 1; Ok(DataType::Float) }
        'N' => { *index += 1; Ok(DataType::Double) }
        'O' => { *index += 1; Ok(DataType::LongDouble) }
        'Z' => { *index += 1; Ok(DataType::VarArgs) }
        '_' => {
            // Extended types: _J = __int64, _N = __int128, _W = wchar_t, etc.
            if *index + 1 < chars.len() {
                let ext_code = chars[*index + 1];
                match ext_code {
                    'J' => { *index += 2; Ok(DataType::Int64 { sign: Sign::Signed }) }
                    'K' => { *index += 2; Ok(DataType::Int64 { sign: Sign::Unsigned }) }
                    'N' => { *index += 2; Ok(DataType::Int128 { sign: Sign::Signed }) }
                    'O' => { *index += 2; Ok(DataType::Int128 { sign: Sign::Unsigned }) }
                    'W' => { *index += 2; Ok(DataType::WChar) }
                    'Q' => { *index += 2; Ok(DataType::Char { sign: Sign::SpecifiedSigned }) }
                    'S' => { *index += 2; Ok(DataType::Char { sign: Sign::Signed }) }
                    'T' => { *index += 2; Ok(DataType::Char { sign: Sign::Unsigned }) }
                    'U' => { *index += 2; Ok(DataType::Short { sign: Sign::SpecifiedSigned }) }
                    'V' => { *index += 2; Ok(DataType::Short { sign: Sign::Unsigned }) }
                    'X' => { *index += 2; Ok(DataType::Int { sign: Sign::SpecifiedSigned }) }
                    'Y' => { *index += 2; Ok(DataType::Int { sign: Sign::Unsigned }) }
                    'Z' => { *index += 2; Ok(DataType::Bool) }
                    _ => Err(format!("Unknown extended type code: _{}", ext_code)),
                }
            } else {
                Err("Unexpected end after '_' in type code".to_string())
            }
        }
        // Named types (class, struct, union, enum)
        'T' => {
            // Union
            *index += 1;
            Ok(DataType::Union {
                name: "?union?".to_string(),
            })
        }
        'U' => {
            // Struct
            *index += 1;
            Ok(DataType::Struct {
                name: "?struct?".to_string(),
            })
        }
        'V' => {
            // Class
            *index += 1;
            Ok(DataType::Class {
                name: "?class?".to_string(),
            })
        }
        'W' => {
            // Enum
            *index += 1;
            // Parse the underlying type and name
            Ok(DataType::Enum {
                name: "?enum?".to_string(),
                underlying: None,
            })
        }
        // Void type (used in argument lists as terminator)
        '@' => {
            // Type list terminator; not a type itself
            Err("Type list terminator '@' encountered in type parsing".to_string())
        }
        _ => Err(format!("Unknown type code: {}", code)),
    }
}

/// Parse a single basic data type (non-pointer, non-reference, non-modifier).
pub fn parse_basic_data_type(chars: &[char], index: &mut usize) -> Result<DataType, String> {
    parse_primary_data_type(chars, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn test_parse_void() {
        let chars = to_chars("X");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::Void));
        assert_eq!(index, 1);
    }

    #[test]
    fn test_parse_int() {
        let chars = to_chars("H");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::Int { sign: Sign::Signed }));
    }

    #[test]
    fn test_parse_unsigned_int() {
        let chars = to_chars("I");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::Int { sign: Sign::Unsigned }));
    }

    #[test]
    fn test_parse_char() {
        let chars = to_chars("C");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::Char { sign: Sign::SpecifiedSigned }));
    }

    #[test]
    fn test_parse_float() {
        let chars = to_chars("M");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::Float));
    }

    #[test]
    fn test_parse_double() {
        let chars = to_chars("N");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::Double));
    }

    #[test]
    fn test_parse_pointer_to_int() {
        let chars = to_chars("PH");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        if let DataType::Pointer { pointed_to, .. } = dt {
            assert!(matches!(*pointed_to, DataType::Int { sign: Sign::Signed }));
        } else {
            panic!("Expected pointer type");
        }
    }

    #[test]
    fn test_parse_reference_to_int() {
        let chars = to_chars("QH");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        if let DataType::Reference { pointed_to, .. } = dt {
            assert!(matches!(*pointed_to, DataType::Int { sign: Sign::Signed }));
        } else {
            panic!("Expected reference type");
        }
    }

    #[test]
    fn test_parse_int64() {
        let chars = to_chars("_J");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::Int64 { sign: Sign::Signed }));
        assert_eq!(index, 2);
    }

    #[test]
    fn test_parse_wchar_t() {
        let chars = to_chars("_W");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::WChar));
    }

    #[test]
    fn test_parse_bool() {
        let chars = to_chars("_Z");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::Bool));
    }

    #[test]
    fn test_parse_varargs() {
        let chars = to_chars("Z");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::VarArgs));
    }

    #[test]
    fn test_parse_pointer_to_pointer() {
        let chars = to_chars("PPH");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        if let DataType::Pointer { pointed_to, .. } = dt {
            if let DataType::Pointer { pointed_to: inner, .. } = *pointed_to {
                assert!(matches!(*inner, DataType::Int { sign: Sign::Signed }));
            } else {
                panic!("Expected inner pointer type");
            }
        } else {
            panic!("Expected pointer type");
        }
    }

    #[test]
    fn test_parse_right_reference() {
        let chars = to_chars("RH");
        let mut index = 0;
        let dt = parse_data_type(&chars, &mut index).unwrap();
        assert!(matches!(dt, DataType::RightReference { .. }));
    }

    #[test]
    fn test_unknown_type() {
        let chars = to_chars("!");
        let mut index = 0;
        let result = parse_data_type(&chars, &mut index);
        assert!(result.is_err());
    }

    #[test]
    fn test_type_display() {
        assert_eq!(DataType::Void.to_string(), "void");
        assert_eq!(
            DataType::Int {
                sign: Sign::Unsigned
            }
            .to_string(),
            "unsigned int"
        );
        let ptr = DataType::Pointer {
            pointed_to: Box::new(DataType::Float),
            cv_mod: None,
        };
        assert_eq!(ptr.to_string(), "float *");
    }
}
