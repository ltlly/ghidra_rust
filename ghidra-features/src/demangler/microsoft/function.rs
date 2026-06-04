//! Function type representation for Microsoft demangling.
//!
//! Ported from `mdemangler.functiontype.*` Java classes.

use crate::demangler::microsoft::datatype::DataType;
use crate::demangler::microsoft::modifier::CVMod;
use std::fmt;

// ---------------------------------------------------------------------------
// CallingConvention
// ---------------------------------------------------------------------------

/// Calling convention for a function.
///
/// Ported from `MDCallingConvention.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    Cdecl,
    Pascal,
    Thiscall,
    Stdcall,
    Fastcall,
    Clrcall,
    Eabi,
    Vectorcall,
    Regcall,
}

impl CallingConvention {
    /// Parse a calling convention from the mangled character.
    ///
    /// Characters 'A'-'B' map to `__cdecl`, 'C'-'D' to `__pascal`,
    /// 'E'-'F' to `__thiscall`, etc.
    pub fn from_char(ch: char) -> Option<Self> {
        match ch {
            'A' | 'B' => Some(CallingConvention::Cdecl),
            'C' | 'D' => Some(CallingConvention::Pascal),
            'E' | 'F' => Some(CallingConvention::Thiscall),
            'G' | 'H' => Some(CallingConvention::Stdcall),
            'I' | 'J' => Some(CallingConvention::Fastcall),
            'K' | 'L' => Some(CallingConvention::Clrcall),
            'M' | 'N' => Some(CallingConvention::Eabi),
            'O' | 'P' => Some(CallingConvention::Vectorcall),
            'Q' | 'R' => Some(CallingConvention::Regcall),
            _ => None,
        }
    }

    /// Returns true if the calling convention character indicates an exported symbol.
    pub fn is_exported(ch: char) -> bool {
        ((ch as u8).wrapping_sub(b'A') % 2) == 1
    }

    /// Returns the human-readable name of the calling convention.
    pub fn name(&self) -> &str {
        match self {
            CallingConvention::Cdecl => "__cdecl",
            CallingConvention::Pascal => "__pascal",
            CallingConvention::Thiscall => "__thiscall",
            CallingConvention::Stdcall => "__stdcall",
            CallingConvention::Fastcall => "__fastcall",
            CallingConvention::Clrcall => "__clrcall",
            CallingConvention::Eabi => "__eabi",
            CallingConvention::Vectorcall => "__vectorcall",
            CallingConvention::Regcall => "__regcall",
        }
    }
}

impl fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// FunctionType
// ---------------------------------------------------------------------------

/// A function type within a Microsoft mangled symbol.
///
/// Ported from `MDFunctionType.java`.
#[derive(Debug, Clone)]
pub struct FunctionType {
    /// The calling convention.
    pub convention: CallingConvention,
    /// The return type (None for constructors/destructors).
    pub return_type: Option<DataType>,
    /// The argument types.
    pub args: Vec<DataType>,
    /// The `this`-pointer CV modifier (for member functions).
    pub this_cv_mod: Option<CVMod>,
    /// Throw attribute (the `Z` suffix indicating throw()).
    pub has_throw_attribute: bool,
    /// Whether this is a function with a CV modifier (member function).
    pub has_cv_modifier: bool,
    /// Whether this function has arguments.
    pub has_args: bool,
    /// Whether this function has a return type.
    pub has_return: bool,
    /// Whether this is a type-cast operator.
    pub is_type_cast: bool,
    /// Whether this function type comes from a modifier.
    pub from_modifier: bool,
}

impl FunctionType {
    /// Create a new function type with default settings.
    pub fn new(convention: CallingConvention) -> Self {
        Self {
            convention,
            return_type: None,
            args: Vec::new(),
            this_cv_mod: None,
            has_throw_attribute: false,
            has_cv_modifier: false,
            has_args: true,
            has_return: true,
            is_type_cast: false,
            from_modifier: false,
        }
    }

    /// Create a function type with specific arg/return settings.
    pub fn with_flags(
        convention: CallingConvention,
        has_args: bool,
        has_return: bool,
    ) -> Self {
        Self {
            convention,
            has_args,
            has_return,
            ..Self::new(CallingConvention::Cdecl)
        }
    }

    /// Emit the function signature as a string.
    ///
    /// The output format is:
    /// `[return_type] [convention] ([args]) [throw_attribute]`
    pub fn emit(&self, base_name: &str) -> String {
        let mut parts = Vec::new();

        // Return type
        if self.has_return {
            if let Some(ref ret) = self.return_type {
                let ret_str = ret.emit();
                if !ret_str.is_empty() {
                    parts.push(ret_str);
                }
            }
        }

        // Calling convention
        parts.push(self.convention.name().to_string());

        // Function name with parentheses
        if self.from_modifier {
            parts.push(format!("({})", base_name));
        } else {
            parts.push(base_name.to_string());
        }

        // Arguments
        if self.has_args {
            let args_str = if self.args.is_empty() {
                "void".to_string()
            } else {
                self.args
                    .iter()
                    .map(|a| a.emit())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            parts.push(format!("({})", args_str));
        }

        // This-pointer CV modifier
        if let Some(ref cv) = self.this_cv_mod {
            if cv.has_qualifier() {
                parts.push(cv.to_string());
            }
        }

        // Throw attribute
        if self.has_throw_attribute {
            parts.push("throw()".to_string());
        }

        parts.join(" ")
    }
}

impl fmt::Display for FunctionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(""))
    }
}

// ---------------------------------------------------------------------------
// ThrowAttribute
// ---------------------------------------------------------------------------

/// Throw attribute for a function type.
///
/// Ported from `MDThrowAttribute.java`.
#[derive(Debug, Clone)]
pub struct ThrowAttribute;

impl ThrowAttribute {
    /// Parse the throw attribute. In the mangled string, this is `Z`.
    pub fn parse(ch: char) -> Option<Self> {
        if ch == 'Z' {
            Some(ThrowAttribute)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calling_convention_parse() {
        assert_eq!(
            CallingConvention::from_char('A'),
            Some(CallingConvention::Cdecl)
        );
        assert_eq!(
            CallingConvention::from_char('B'),
            Some(CallingConvention::Cdecl)
        );
        assert_eq!(
            CallingConvention::from_char('E'),
            Some(CallingConvention::Thiscall)
        );
        assert_eq!(
            CallingConvention::from_char('G'),
            Some(CallingConvention::Stdcall)
        );
        assert_eq!(
            CallingConvention::from_char('I'),
            Some(CallingConvention::Fastcall)
        );
        assert_eq!(CallingConvention::from_char('Z'), None);
    }

    #[test]
    fn test_calling_convention_exported() {
        assert!(!CallingConvention::is_exported('A')); // even = not exported
        assert!(CallingConvention::is_exported('B'));  // odd = exported
    }

    #[test]
    fn test_function_type_emit() {
        let mut ft = FunctionType::new(CallingConvention::Cdecl);
        ft.return_type = Some(DataType::Int {
            sign: crate::demangler::microsoft::datatype::Sign::Signed,
        });
        ft.args = vec![
            DataType::Int {
                sign: crate::demangler::microsoft::datatype::Sign::Signed,
            },
            DataType::Float,
        ];
        let output = ft.emit("foo");
        assert!(output.contains("int"));
        assert!(output.contains("__cdecl"));
        assert!(output.contains("foo"));
        assert!(output.contains("int"));
        assert!(output.contains("float"));
    }

    #[test]
    fn test_function_type_void_args() {
        let mut ft = FunctionType::new(CallingConvention::Stdcall);
        ft.return_type = Some(DataType::Void);
        ft.args = vec![];
        let output = ft.emit("bar");
        assert!(output.contains("void"));
        assert!(output.contains("__stdcall"));
    }

    #[test]
    fn test_throw_attribute() {
        assert!(ThrowAttribute::parse('Z').is_some());
        assert!(ThrowAttribute::parse('X').is_none());
    }
}
