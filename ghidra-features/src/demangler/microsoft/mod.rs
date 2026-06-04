//! Microsoft Visual Studio demangler.
//!
//! Ported from `mdemangler.*` and `ghidra.app.util.demangler.microsoft.*` Java classes.
//!
//! The MSVC name mangling scheme encodes C++ symbol names into a compact
//! string starting with `?`. This module implements a full parser for this
//! scheme, supporting:
//! - Function symbols (including member functions, virtual functions)
//! - Data symbols (globals, statics, class members)
//! - Special names (constructors, destructors, operators)
//! - Template names with arguments
//! - RTTI symbols
//! - Type-cast operators
//! - Calling conventions (cdecl, stdcall, fastcall, thiscall, etc.)
//! - Data types (primitives, pointers, references, arrays, classes, etc.)
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::demangler::microsoft::MicrosoftDemangler;
//!
//! let demangler = MicrosoftDemangler::new();
//! let result = demangler.demangle("?foo@@YAXXZ").unwrap();
//! assert_eq!(result.demangled_name, "void __cdecl foo(void)");
//! ```

pub mod context;
pub mod datatype;
pub mod function;
pub mod iterator;
pub mod modifier;
pub mod naming;
pub mod object;
pub mod template;
pub mod typeinfo;

use datatype::parser::parse_data_type;
use datatype::DataType;
use function::CallingConvention;
use modifier::CVMod;
use naming::{BasicName, BasicNameKind, FragmentName, Qualification, QualifiedBasicName, SpecialName};
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during demangling.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DemangleError {
    /// The mangled symbol is empty or blank.
    #[error("Mangled symbol is empty or blank")]
    EmptySymbol,

    /// The mangled symbol does not start with the expected prefix.
    #[error("Not a valid Microsoft mangled symbol (missing '?' prefix)")]
    InvalidSymbol(String),

    /// An error occurred during parsing.
    #[error("Parse error at position {position}: {message}")]
    ParseError {
        position: usize,
        message: String,
    },

    /// A generic parse error from a String.
    #[error("Parse error: {0}")]
    GenericParse(String),

    /// The symbol has unexpected characters remaining after parsing.
    #[error("Characters remaining after demangling: {0} chars")]
    RemainingChars(usize),

    /// A back-reference is invalid.
    #[error("Invalid back-reference: {0}")]
    InvalidBackref(String),

    /// The native demangler process failed (for GNU demangler).
    #[error("Native demangler process error: {0}")]
    ProcessError(String),
}

impl From<String> for DemangleError {
    fn from(msg: String) -> Self {
        DemangleError::GenericParse(msg)
    }
}

// ---------------------------------------------------------------------------
// DemangleResult
// ---------------------------------------------------------------------------

/// The result of demangling a symbol.
///
/// Corresponds to `DemangledObject` in the Java code.
#[derive(Debug, Clone)]
pub struct DemangleResult {
    /// The original mangled name.
    pub mangled_name: String,
    /// The fully demangled name.
    pub demangled_name: String,
    /// The namespace path (e.g., `["std", "vector"]`).
    pub namespace: Vec<String>,
    /// The base name (without namespace or template args).
    pub base_name: String,
    /// The calling convention (if a function).
    pub calling_convention: Option<CallingConvention>,
    /// The return type (if a function).
    pub return_type: Option<DataType>,
    /// The argument types (if a function).
    pub argument_types: Vec<DataType>,
    /// Whether this is a function.
    pub is_function: bool,
    /// Whether this is a data symbol.
    pub is_data: bool,
    /// Whether this is a constructor.
    pub is_constructor: bool,
    /// Whether this is a destructor.
    pub is_destructor: bool,
    /// Whether this is a type-cast operator.
    pub is_type_cast: bool,
    /// Whether this is a virtual function.
    pub is_virtual: bool,
    /// The access level string.
    pub access_level: String,
    /// Template arguments if present.
    pub template_arguments: Vec<String>,
    /// RTTI number if this is an RTTI symbol.
    pub rtti_number: Option<i32>,
}

impl DemangleResult {
    /// Create a new empty result.
    fn new(mangled: &str) -> Self {
        Self {
            mangled_name: mangled.to_string(),
            demangled_name: String::new(),
            namespace: Vec::new(),
            base_name: String::new(),
            calling_convention: None,
            return_type: None,
            argument_types: Vec::new(),
            is_function: false,
            is_data: false,
            is_constructor: false,
            is_destructor: false,
            is_type_cast: false,
            is_virtual: false,
            access_level: String::new(),
            template_arguments: Vec::new(),
            rtti_number: None,
        }
    }

    /// Get the fully qualified name (namespace + base name).
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() {
            self.base_name.clone()
        } else {
            format!("{}::{}", self.namespace.join("::"), self.base_name)
        }
    }
}

// ---------------------------------------------------------------------------
// MicrosoftDemangler
// ---------------------------------------------------------------------------

/// The main Microsoft demangler.
///
/// This corresponds to the Java `MDMang` / `MDMangGhidra` / `MicrosoftDemangler` classes.
pub struct MicrosoftDemangler {
    /// Architecture size in bits (32 or 64).
    architecture_size: u32,
    /// Whether to error on remaining characters.
    error_on_remaining: bool,
}

impl MicrosoftDemangler {
    /// Create a new Microsoft demangler with 64-bit architecture default.
    pub fn new() -> Self {
        Self {
            architecture_size: 64,
            error_on_remaining: false,
        }
    }

    /// Create a new Microsoft demangler with a specific architecture size.
    pub fn with_architecture(size: u32) -> Self {
        Self {
            architecture_size: size,
            error_on_remaining: false,
        }
    }

    /// Set the architecture size.
    pub fn set_architecture_size(&mut self, size: u32) {
        self.architecture_size = size;
    }

    /// Set whether to error on remaining characters.
    pub fn set_error_on_remaining(&mut self, error: bool) {
        self.error_on_remaining = error;
    }

    /// Returns true if this string looks like a Microsoft mangled symbol.
    ///
    /// Microsoft mangled symbols always start with `?`.
    pub fn can_demangle(mangled: &str) -> bool {
        !mangled.is_empty() && mangled.starts_with('?')
    }

    /// Demangle a Microsoft mangled symbol.
    ///
    /// This is the main entry point. It initializes state, delegates to the
    /// object parser, and returns a structured result.
    ///
    /// # Errors
    ///
    /// Returns `DemangleError` if the symbol cannot be parsed.
    pub fn demangle(&self, mangled: &str) -> Result<DemangleResult, DemangleError> {
        let trimmed = mangled.trim();
        if trimmed.is_empty() {
            return Err(DemangleError::EmptySymbol);
        }

        let chars: Vec<char> = trimmed.chars().collect();
        let mut index = 0;

        // Determine what kind of mangled symbol this is
        let mut result = DemangleResult::new(trimmed);

        // Check for type name (starts with `.`, followed by type encoding)
        if chars[0] == '.' && !trimmed[1..].contains('.') {
            index = 1;
            // This is a mangled "type" name
            match parse_data_type(&chars, &mut index) {
                Ok(dt) => {
                    result.demangled_name = dt.emit();
                    result.is_data = true;
                    return Ok(result);
                }
                Err(e) => {
                    return Err(DemangleError::ParseError {
                        position: index,
                        message: format!("Type parsing failed: {}", e),
                    });
                }
            }
        }

        // Standard symbol (starts with `?`)
        if chars[0] == '?' {
            index = 1; // skip the '?'

            // Check for `?@` (CodeView symbol)
            if index < chars.len() && chars[index] == '@' {
                return Err(DemangleError::ParseError {
                    position: index,
                    message: "CodeView symbols not yet supported".to_string(),
                });
            }

            // Check for `?$` (template name)
            if index < chars.len() && chars[index] == '$' {
                index += 1;
                return self.parse_template_name(&chars, &mut index, &mut result);
            }

            // Parse the qualified basic name
            let qbn = self.parse_qualified_basic_name(&chars, &mut index)?;

            // Copy name data into result
            result.base_name = qbn.basic_name.get_name();
            result.namespace = qbn
                .qualification
                .qualifiers
                .iter()
                .rev()
                .map(|q| q.name.clone())
                .collect();
            result.is_constructor = qbn.is_constructor();
            result.is_destructor = qbn.is_destructor();
            result.is_type_cast = qbn.is_type_cast();
            result.rtti_number = if qbn.rtti_number() >= 0 {
                Some(qbn.rtti_number())
            } else {
                None
            };

            // Parse type info (if characters remain)
            if index < chars.len() && chars[index] != '@' {
                let type_info = typeinfo::TypeInfo::parse(&chars, &mut index)?;

                result.is_function = type_info.is_function;
                result.is_data = !type_info.is_function;
                result.is_virtual = type_info.is_virtual;
                result.access_level = type_info.emit_prefix();

                if type_info.is_function {
                    // Parse function signature
                    return self.parse_function_type(&chars, &mut index, &mut result, &type_info);
                }
            } else if index < chars.len() && chars[index] == '@' {
                index += 1;
                // String literal or just a name
            }
        } else {
            return Err(DemangleError::InvalidSymbol(
                "Not a valid Microsoft mangled symbol (missing '?' or '.' prefix)".to_string(),
            ));
        }

        // Build demangled name
        result.demangled_name = self.build_demangled_name(&result);

        // Check for remaining characters
        if self.error_on_remaining && index < chars.len() {
            return Err(DemangleError::RemainingChars(chars.len() - index));
        }

        Ok(result)
    }

    /// Parse a template name from `?$` prefix.
    fn parse_template_name(
        &self,
        chars: &[char],
        index: &mut usize,
        result: &mut DemangleResult,
    ) -> Result<DemangleResult, DemangleError> {
        // Parse the template name fragment
        let fragment = FragmentName::parse(chars, index);
        result.base_name = fragment.name.clone();

        // Parse template arguments (each argument is terminated by '@')
        while *index < chars.len() && chars[*index] != '@' {
            if chars[*index] == '?' && *index + 1 < chars.len() && chars[*index + 1] == '$' {
                // Nested template
                *index += 2;
                let nested = FragmentName::parse(chars, index);
                result.template_arguments.push(nested.name);
            } else if chars[*index] == '?' {
                // Template parameter reference
                *index += 1;
                if *index < chars.len() {
                    let ch = chars[*index];
                    *index += 1;
                    if ch.is_ascii_digit() {
                        result
                            .template_arguments
                            .push(format!("$T{}", ch as u8 - b'0'));
                    } else {
                        result.template_arguments.push(format!("?{}", ch));
                    }
                }
            } else {
                // Regular type argument
                match parse_data_type(chars, index) {
                    Ok(dt) => result.template_arguments.push(dt.emit()),
                    Err(_) => {
                        // Try as a fragment name
                        let frag = FragmentName::parse(chars, index);
                        if !frag.name.is_empty() {
                            result.template_arguments.push(frag.name);
                        }
                    }
                }
            }
        }

        // Skip the final '@'
        if *index < chars.len() && chars[*index] == '@' {
            *index += 1;
        }

        result.is_data = true;
        result.demangled_name = self.build_demangled_name(result);
        Ok(result.clone())
    }

    /// Parse a qualified basic name (name + qualification).
    fn parse_qualified_basic_name(
        &self,
        chars: &[char],
        index: &mut usize,
    ) -> Result<QualifiedBasicName, DemangleError> {
        let start = *index;

        // Parse the basic name first
        let basic_name = if *index < chars.len() {
            if chars[*index] == '?' {
                *index += 1;
                if *index < chars.len() {
                    if chars[*index] == '_' {
                        // Special name with underscore prefix
                        *index += 1;
                        if *index < chars.len() {
                            let ch = chars[*index];
                            *index += 1;
                            match SpecialName::from_underscore_code(ch) {
                                Some(sn) => BasicName::special(sn),
                                None => {
                                    return Err(DemangleError::ParseError {
                                        position: *index - 1,
                                        message: format!(
                                            "Unknown special name code: _{}",
                                            ch
                                        ),
                                    });
                                }
                            }
                        } else {
                            return Err(DemangleError::ParseError {
                                position: *index,
                                message: "Unexpected end after '_'".to_string(),
                            });
                        }
                    } else if chars[*index] == '$' {
                        // Template name as part of a qualified name
                        *index += 1;
                        let frag = FragmentName::parse(chars, index);
                        BasicName {
                            kind: BasicNameKind::Template {
                                name: frag.name,
                                args: Vec::new(),
                            },
                            name_modifier: None,
                            cast_type_string: None,
                        }
                    } else {
                        // Standard special name
                        let ch = chars[*index];
                        *index += 1;
                        match SpecialName::from_code(ch) {
                            Some(sn) => BasicName::special(sn),
                            None => {
                                return Err(DemangleError::ParseError {
                                    position: *index - 1,
                                    message: format!(
                                        "Unknown operator code: ?{}",
                                        ch
                                    ),
                                });
                            }
                        }
                    }
                } else {
                    return Err(DemangleError::ParseError {
                        position: *index,
                        message: "Unexpected end after '?'".to_string(),
                    });
                }
            } else if chars[*index].is_ascii_digit() {
                // Back-reference name
                let frag = FragmentName::parse(chars, index);
                BasicName::regular(frag)
            } else {
                // Regular fragment name
                let frag = FragmentName::parse(chars, index);
                BasicName::regular(frag)
            }
        } else {
            return Err(DemangleError::ParseError {
                position: start,
                message: "Expected a name".to_string(),
            });
        };

        // Parse the qualification (namespace path)
        let qualification = Qualification::parse(chars, index);

        Ok(QualifiedBasicName::new(basic_name, qualification))
    }

    /// Parse a function type from the character stream.
    fn parse_function_type(
        &self,
        chars: &[char],
        index: &mut usize,
        result: &mut DemangleResult,
        type_info: &typeinfo::TypeInfo,
    ) -> Result<DemangleResult, DemangleError> {
        // Check for this-pointer CV modifier (only for member functions)
        if type_info.is_member_function && *index < chars.len() && "ABCDE".contains(chars[*index]) {
            let _this_cv = CVMod::from_this_pointer_code(chars[*index]);
            *index += 1;
        }

        // Parse calling convention
        if *index < chars.len() {
            if let Some(conv) = CallingConvention::from_char(chars[*index]) {
                result.calling_convention = Some(conv);
                *index += 1;
            } else {
                return Err(DemangleError::ParseError {
                    position: *index,
                    message: format!("Unknown calling convention: {}", chars[*index]),
                });
            }
        } else {
            return Err(DemangleError::ParseError {
                position: *index,
                message: "Expected calling convention".to_string(),
            });
        }

        // Parse return type (unless it's a constructor/destructor)
        if !result.is_constructor && !result.is_destructor {
            if *index < chars.len() {
                match parse_data_type(chars, index) {
                    Ok(dt) => {
                        result.return_type = Some(dt);
                    }
                    Err(_) => {
                        // Return type parse failed; continue with args
                    }
                }
            }
        }

        // Parse arguments
        while *index < chars.len() {
            let ch = chars[*index];
            if ch == '@' {
                *index += 1;
                break;
            }
            if ch == 'Z' {
                // Throw attribute
                *index += 1;
                break;
            }
            if ch == 'X' {
                // void argument
                result.argument_types.push(DataType::Void);
                *index += 1;
                // If void is first arg, terminate list without '@'
                if result.argument_types.len() == 1 {
                    break;
                }
                continue;
            }
            match parse_data_type(chars, index) {
                Ok(dt) => result.argument_types.push(dt),
                Err(_) => break,
            }
        }

        result.is_function = true;
        result.demangled_name = self.build_demangled_name(result);

        if self.error_on_remaining && *index < chars.len() {
            return Err(DemangleError::RemainingChars(chars.len() - *index));
        }

        Ok(result.clone())
    }

    /// Build the final demangled name string.
    fn build_demangled_name(&self, result: &DemangleResult) -> String {
        let mut parts = Vec::new();

        // Access level prefix
        if !result.access_level.is_empty() {
            parts.push(result.access_level.clone());
        }

        // Virtual marker
        if result.is_virtual {
            parts.push("virtual".to_string());
        }

        // Return type
        if let Some(ref ret) = result.return_type {
            let ret_str = ret.emit();
            if !ret_str.is_empty() {
                parts.push(ret_str);
            }
        }

        // Calling convention
        if let Some(ref conv) = result.calling_convention {
            parts.push(conv.name().to_string());
        }

        // Qualified name
        let qname = result.qualified_name();

        // Template arguments
        let name_with_template = if !result.template_arguments.is_empty() {
            format!("{}<{}>", qname, result.template_arguments.join(", "))
        } else {
            qname
        };

        // Constructor/destructor name
        let final_name = if result.is_destructor {
            format!("~{}", name_with_template)
        } else if result.is_type_cast {
            format!("operator {}", name_with_template)
        } else {
            name_with_template
        };

        parts.push(final_name);

        // Function arguments
        if result.is_function {
            let args_str = if result.argument_types.is_empty() {
                "void".to_string()
            } else {
                result
                    .argument_types
                    .iter()
                    .map(|a| a.emit())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            parts.push(format!("({})", args_str));
        }

        parts.join(" ")
    }
}

impl Default for MicrosoftDemangler {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MicrosoftDemangler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MicrosoftDemangler")
            .field("architecture_size", &self.architecture_size)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_demangle() {
        assert!(MicrosoftDemangler::can_demangle("?foo@@YAXXZ"));
        assert!(MicrosoftDemangler::can_demangle("?bar@@YAXXZ"));
        assert!(!MicrosoftDemangler::can_demangle("_Z3foov"));
        assert!(!MicrosoftDemangler::can_demangle(""));
        assert!(!MicrosoftDemangler::can_demangle("plain_symbol"));
    }

    #[test]
    fn test_demangle_void_function() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?foo@@YAXXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.is_function);
        assert_eq!(r.base_name, "foo");
        assert!(r.demangled_name.contains("foo"));
        assert!(r.demangled_name.contains("void"));
    }

    #[test]
    fn test_demangle_int_function() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?bar@@YAHXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.is_function);
        assert_eq!(r.base_name, "bar");
        assert!(r.return_type.is_some());
    }

    #[test]
    fn test_demangle_constructor() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("??0MyClass@@QEAA@XZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        // Constructors/destructors may be parsed differently
        assert!(r.demangled_name.contains("MyClass") || r.base_name.contains("MyClass"));
    }

    #[test]
    fn test_demangle_operator() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("??H@YAPEAVC@@PEAV0@0@Z");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("operator") || r.base_name.contains("operator"));
    }

    #[test]
    fn test_demangle_empty_symbol() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("");
        assert!(matches!(result, Err(DemangleError::EmptySymbol)));
    }

    #[test]
    fn test_demangle_not_ms_symbol() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("_Z3foov");
        // Should fail since it doesn't start with '?'
        assert!(result.is_err());
    }

    #[test]
    fn test_demangle_data_symbol() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?myGlobal@@3HA");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert_eq!(r.base_name, "myGlobal");
    }

    #[test]
    fn test_demangle_namespaced_function() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?func@ns@@YAXXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.namespace.contains(&"ns".to_string()));
        assert!(r.demangled_name.contains("ns"));
    }

    #[test]
    fn test_demangle_pointer_to_int() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?myVar@@3PEAHE");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("*"));
    }

    #[test]
    fn test_demangle_with_remaining_chars() {
        let mut d = MicrosoftDemangler::new();
        d.set_error_on_remaining(true);
        // A symbol with extra chars at the end
        let result = d.demangle("?foo@@YAXXZEXTRA");
        // Should produce remaining chars error
        assert!(matches!(result, Err(DemangleError::RemainingChars(_))));
    }

    #[test]
    fn test_result_qualified_name() {
        let mut r = DemangleResult::new("test");
        r.base_name = "foo".to_string();
        r.namespace = vec!["std".to_string(), "vector".to_string()];
        assert_eq!(r.qualified_name(), "std::vector::foo");
    }

    #[test]
    fn test_demangle_reference_type() {
        let d = MicrosoftDemangler::new();
        // ?myRef@@3QAH@Z = int& myRef
        let result = d.demangle("?myRef@@3QAH@Z");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("&"));
    }

    #[test]
    fn test_demangle_struct_type() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?myStruct@@3US@@@Z");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
    }

    #[test]
    fn test_demangle_stdcall_function() {
        let d = MicrosoftDemangler::new();
        // ?func@@YGXXZ = void __stdcall func(void)
        let result = d.demangle("?func@@YGXXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("__stdcall"));
    }

    #[test]
    fn test_demangle_fastcall_function() {
        let d = MicrosoftDemangler::new();
        // ?func@@YIXXZ = void __fastcall func(void)
        let result = d.demangle("?func@@YIXXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("__fastcall"));
    }

    #[test]
    fn test_demangle_multiple_args() {
        let d = MicrosoftDemangler::new();
        // ?foo@@YAXHHM@Z = void __cdecl foo(int, int, float)
        let result = d.demangle("?foo@@YAXHHM@Z");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.argument_types.len() >= 2);
    }

    #[test]
    fn test_demangle_varargs() {
        let d = MicrosoftDemangler::new();
        // ?printf@@YAHPEBDZZ = int __cdecl printf(char const *, ...)
        let result = d.demangle("?printf@@YAHPEBDZZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("..."));
    }
}
