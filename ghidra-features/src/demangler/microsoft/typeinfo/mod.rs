//! Type info parsing for Microsoft demangling.
//!
//! Ported from `mdemangler.typeinfo.*` Java classes.
//!
//! Type info encodes the function/data characteristics of a symbol:
//! - Access level (public, private, protected, etc.)
//! - Storage class (static, virtual, extern, etc.)
//! - Pointer format
//! - Member function vs. free function

use crate::demangler::microsoft::function::FunctionType;
use crate::demangler::microsoft::modifier::CVMod;

// ---------------------------------------------------------------------------
// AccessLevel
// ---------------------------------------------------------------------------

/// Access level / storage class for a symbol.
///
/// Ported from `MDTypeInfoParser.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLevel {
    /// Private static member
    PrivateStatic,
    /// Protected static member
    ProtectedStatic,
    /// Public static member
    PublicStatic,
    /// Non-static private member
    PrivateNonStatic,
    /// Non-static protected member
    ProtectedNonStatic,
    /// Non-static public member
    PublicNonStatic,
    /// Global (no access level)
    Global,
    /// Extern "C" global
    ExternC,
    /// Static local variable
    StaticLocal,
    /// Local variable
    Local,
}

impl AccessLevel {
    /// Returns true if this is a static storage class.
    pub fn is_static(&self) -> bool {
        matches!(
            self,
            AccessLevel::PrivateStatic
                | AccessLevel::ProtectedStatic
                | AccessLevel::PublicStatic
                | AccessLevel::StaticLocal
        )
    }

    /// Returns true if this is a member (not global/extern/local).
    pub fn is_member(&self) -> bool {
        matches!(
            self,
            AccessLevel::PrivateNonStatic
                | AccessLevel::ProtectedNonStatic
                | AccessLevel::PublicNonStatic
                | AccessLevel::PrivateStatic
                | AccessLevel::ProtectedStatic
                | AccessLevel::PublicStatic
        )
    }

    /// Returns the human-readable access modifier string.
    pub fn modifier_string(&self) -> &str {
        match self {
            AccessLevel::PrivateStatic => "private: static",
            AccessLevel::ProtectedStatic => "protected: static",
            AccessLevel::PublicStatic => "public: static",
            AccessLevel::PrivateNonStatic => "private:",
            AccessLevel::ProtectedNonStatic => "protected:",
            AccessLevel::PublicNonStatic => "public:",
            AccessLevel::Global => "",
            AccessLevel::ExternC => "extern \"C\"",
            AccessLevel::StaticLocal => "static local",
            AccessLevel::Local => "local",
        }
    }
}

// ---------------------------------------------------------------------------
// TypeInfo
// ---------------------------------------------------------------------------

/// Parsed type information for a symbol.
///
/// Ported from `MDTypeInfo.java`.
#[derive(Debug, Clone)]
pub struct TypeInfo {
    /// The access level.
    pub access_level: AccessLevel,
    /// Whether the symbol is virtual.
    pub is_virtual: bool,
    /// Whether the symbol is static.
    pub is_static: bool,
    /// Whether the symbol is a member function.
    pub is_member_function: bool,
    /// Whether the symbol is a function at all.
    pub is_function: bool,
    /// The function type (if a function).
    pub function_type: Option<FunctionType>,
    /// The `this`-pointer CV modifier (for member functions).
    pub this_cv_mod: Option<CVMod>,
    /// Whether this is a type-cast operator.
    pub is_type_cast: bool,
    /// Whether this uses extern "C" linkage.
    pub is_extern_c: bool,
    /// Special handling code (for `$$` prefixed types).
    pub special_handling_code: Option<char>,
    /// VT ordisp type.
    pub vtordisp_type: Option<char>,
}

impl TypeInfo {
    /// Create a new type info with default values.
    pub fn new() -> Self {
        Self {
            access_level: AccessLevel::Global,
            is_virtual: false,
            is_static: false,
            is_member_function: false,
            is_function: false,
            function_type: None,
            this_cv_mod: None,
            is_type_cast: false,
            is_extern_c: false,
            special_handling_code: None,
            vtordisp_type: None,
        }
    }

    /// Parse an access-level/type-info code from the character stream.
    ///
    /// The codes are:
    /// - `A` through `T` encode access level, function/data, and near/far
    /// - `$` prefix introduces special handling codes
    /// - `_` prefix introduces additional codes
    pub fn parse(chars: &[char], index: &mut usize) -> Result<Self, String> {
        if *index >= chars.len() {
            return Err("Unexpected end of symbol in TypeInfo parsing".to_string());
        }

        let mut info = Self::new();
        let code = chars[*index];

        match code {
            // Standard access level codes
            'A' => {
                *index += 1;
                info.access_level = AccessLevel::PrivateNonStatic;
                info.is_function = true;
            }
            'B' => {
                *index += 1;
                info.access_level = AccessLevel::PrivateStatic;
                info.is_function = true;
            }
            'C' => {
                *index += 1;
                info.access_level = AccessLevel::ProtectedNonStatic;
                info.is_function = true;
            }
            'D' => {
                *index += 1;
                info.access_level = AccessLevel::ProtectedStatic;
                info.is_function = true;
            }
            'E' => {
                *index += 1;
                info.access_level = AccessLevel::PublicNonStatic;
                info.is_function = true;
            }
            'F' => {
                *index += 1;
                info.access_level = AccessLevel::PublicStatic;
                info.is_function = true;
            }
            'G' => {
                *index += 1;
                info.access_level = AccessLevel::Global;
                info.is_function = true;
            }
            'H' => {
                *index += 1;
                info.access_level = AccessLevel::Global;
                info.is_function = true;
                info.is_static = true;
            }
            'I' => {
                *index += 1;
                info.access_level = AccessLevel::ExternC;
                info.is_function = true;
                info.is_extern_c = true;
            }
            'J' => {
                *index += 1;
                info.access_level = AccessLevel::ExternC;
                info.is_function = true;
                info.is_extern_c = true;
                info.is_static = true;
            }
            'K' => {
                *index += 1;
                info.access_level = AccessLevel::PrivateNonStatic;
                info.is_function = false;
            }
            'L' => {
                *index += 1;
                info.access_level = AccessLevel::PrivateStatic;
                info.is_function = false;
            }
            'M' => {
                *index += 1;
                info.access_level = AccessLevel::ProtectedNonStatic;
                info.is_function = false;
            }
            'N' => {
                *index += 1;
                info.access_level = AccessLevel::ProtectedStatic;
                info.is_function = false;
            }
            'O' => {
                *index += 1;
                info.access_level = AccessLevel::PublicNonStatic;
                info.is_function = false;
            }
            'P' => {
                *index += 1;
                info.access_level = AccessLevel::PublicStatic;
                info.is_function = false;
            }
            'Q' => {
                *index += 1;
                info.access_level = AccessLevel::Global;
                info.is_function = false;
            }
            'R' => {
                *index += 1;
                info.access_level = AccessLevel::Global;
                info.is_function = false;
                info.is_static = true;
            }
            'S' => {
                *index += 1;
                info.access_level = AccessLevel::Global;
                info.is_function = false;
                info.is_static = true;
            }
            'T' => {
                *index += 1;
                info.access_level = AccessLevel::Local;
                info.is_function = false;
            }
            'U' => {
                *index += 1;
                info.access_level = AccessLevel::ExternC;
                info.is_function = true;
                info.is_extern_c = true;
            }
            'V' => {
                *index += 1;
                info.access_level = AccessLevel::ExternC;
                info.is_function = true;
                info.is_extern_c = true;
                info.is_static = true;
            }
            'W' => {
                *index += 1;
                info.access_level = AccessLevel::Global;
                info.is_function = true;
            }
            'X' => {
                *index += 1;
                info.access_level = AccessLevel::Global;
                info.is_function = true;
                info.is_static = true;
            }
            'Y' => {
                *index += 1;
                info.access_level = AccessLevel::Global;
                info.is_function = true;
                info.is_static = true;
            }
            'Z' => {
                *index += 1;
                info.access_level = AccessLevel::Global;
                info.is_function = true;
            }
            '$' => {
                // Special handling codes
                *index += 1;
                if *index < chars.len() {
                    let ch2 = chars[*index];
                    *index += 1;
                    info.special_handling_code = Some(ch2);
                    match ch2 {
                        '0'..='5' => {
                            // Virtual/Member/VTordisp variants
                            let n = (ch2 as u8 - b'0') as i32;
                            info.is_function = true;
                            info.is_virtual = (n % 2) != 0;
                            info.is_member_function = true;
                        }
                        '6'..='9' | 'A'..='E' => {
                            // VTordisp variants
                            info.vtordisp_type = Some(ch2);
                            info.is_function = true;
                            info.is_virtual = true;
                            info.is_member_function = true;
                        }
                        _ => {
                            // Unknown special handling - just store the code
                        }
                    }
                }
            }
            '_' => {
                // Additional codes (deferred types, etc.)
                *index += 1;
                if *index < chars.len() {
                    let ch2 = chars[*index];
                    *index += 1;
                    match ch2 {
                        'A' => {
                            info.access_level = AccessLevel::Local;
                            info.is_function = false;
                        }
                        'B' => {
                            info.access_level = AccessLevel::StaticLocal;
                            info.is_function = false;
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                return Err(format!("Unknown TypeInfo code: {}", code));
            }
        }

        info.is_static |= matches!(
            info.access_level,
            AccessLevel::PrivateStatic
                | AccessLevel::ProtectedStatic
                | AccessLevel::PublicStatic
        );
        info.is_member_function = info.access_level.is_member();

        Ok(info)
    }

    /// Set the type-cast flag.
    pub fn set_type_cast(&mut self) {
        self.is_type_cast = true;
    }

    /// Set extern "C" linkage.
    pub fn set_extern_c(&mut self) {
        self.is_extern_c = true;
    }

    /// Set the special handling code.
    pub fn set_special_handling_code(&mut self, code: char) {
        self.special_handling_code = Some(code);
    }

    /// Emit the type info prefix string (e.g., "public: static").
    pub fn emit_prefix(&self) -> String {
        let mut parts = Vec::new();

        if self.is_virtual {
            parts.push("virtual".to_string());
        }

        let access_str = self.access_level.modifier_string();
        if !access_str.is_empty() {
            parts.push(access_str.to_string());
        }

        parts.join(" ")
    }
}

impl Default for TypeInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_level_parse() {
        let chars: Vec<char> = "A".chars().collect();
        let mut index = 0;
        let info = TypeInfo::parse(&chars, &mut index).unwrap();
        assert_eq!(info.access_level, AccessLevel::PrivateNonStatic);
        assert!(info.is_function);
        assert!(!info.is_static);
    }

    #[test]
    fn test_public_function() {
        let chars: Vec<char> = "YAXXZ".chars().collect();
        let mut index = 0;
        let info = TypeInfo::parse(&chars, &mut index).unwrap();
        assert_eq!(info.access_level, AccessLevel::Global);
        assert!(info.is_function);
        assert!(info.is_static);
    }

    #[test]
    fn test_static_member() {
        let chars: Vec<char> = "B".chars().collect();
        let mut index = 0;
        let info = TypeInfo::parse(&chars, &mut index).unwrap();
        assert_eq!(info.access_level, AccessLevel::PrivateStatic);
        assert!(info.is_static);
    }

    #[test]
    fn test_emit_prefix() {
        let mut info = TypeInfo::new();
        info.access_level = AccessLevel::PublicNonStatic;
        info.is_virtual = true;
        let prefix = info.emit_prefix();
        assert!(prefix.contains("virtual"));
        assert!(prefix.contains("public"));
    }

    #[test]
    fn test_special_handling() {
        let chars: Vec<char> = "$0".chars().collect();
        let mut index = 0;
        let info = TypeInfo::parse(&chars, &mut index).unwrap();
        assert!(info.special_handling_code.is_some());
    }

    #[test]
    fn test_access_level_is_member() {
        assert!(AccessLevel::PrivateNonStatic.is_member());
        assert!(AccessLevel::PublicStatic.is_member());
        assert!(!AccessLevel::Global.is_member());
        assert!(!AccessLevel::Local.is_member());
    }
}
